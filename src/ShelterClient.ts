import { blake3 } from "@noble/hashes/blake3.js";
import nacl from "tweetnacl";
import { readFileSync } from "fs";
import { cwd } from "process";
import path from "path";
import { udpSocket, type udp } from "bun";
import EventEmitter from "events";
import Logger from "./Logger";
import { ShelterPacketType } from "./ShelterPacketType";
import type { ShelterClientOptions } from "./ShelterClientOptions";
import { ShelterUtils } from "./ShelterUtils";
import ShelterClientEvents from "./ShelterClientEvents";
import { ShelterData } from "./types";
import ShelterPacket from "./ShelterPacket";

// ShelterClient is both a client and a server

export default class ShelterClient extends EventEmitter.EventEmitter<ShelterClientEvents> {
  private socket!: udp.Socket<"uint8array">;
  private PORT: number = 4444;

  private _intrinsic = {
    MAGIC: "SHR1",
  };

  private logger: Logger;

  get intrinsic() {
    return this._intrinsic;
  }

  private readonly data = {
    get: () => ShelterUtils.read<ShelterData>(this.datafilePath),
    set: (data: ShelterData) => {
      ShelterUtils.write<ShelterData>(this.datafilePath, data);
    },
  };

  private annuaryPath: string = path.join(cwd(), "shelter_annuary.json");
  private datafilePath: string = path.join(cwd(), "shelter_data.json");

  constructor(options: ShelterClientOptions = {}) {
    super();

    this.datafilePath = options.datafilePath ?? this.datafilePath;
    this.annuaryPath = options.annuaryPath ?? this.annuaryPath;

    this.logger = new Logger(options.debug);

    this.init().then(() => {});

    this.on("ready", () => {
      this.announce();
      this.listenForAnnouncements();
      this.listenForMessages();
      this.listenForSeekResponse();
      this.listenForSeeks();
    });
  }

  /**
   * Get the client's public key (hex)
   */
  get publicKey(): string {
    return this.data.get()!.publicKey;
  }

  /**
   * Get the client's secret key (hex)
   */
  get secretKey(): string {
    return this.data.get()!.secretKey;
  }

  /**
   * Listen for incoming encrypted messages and emit 'text' event
   */
  private listenForMessages() {
    this.on("message", async (data: Uint8Array) => {
      const packet = new ShelterPacket(data);
      if (packet.getType() !== ShelterPacketType.MESSAGE) return;
      const clearText = this.decrypt(data);
      if (!clearText) return;

      this.logger.log(`Received message : ${clearText}`);
      this.emit("text", packet.getSenderHex(), clearText);
    });
  }

  /**
   * Listen for announcement packets and update annuary
   */
  private listenForAnnouncements() {
    this.on("message", async (data: Uint8Array) => {
      const packet = new ShelterPacket(data);
      if (packet.getType() !== ShelterPacketType.ANNOUNCE) return;

      this.logger.log(`Received announcement from ${packet.getSenderHex()}.`);

      // Save to annuary
      let annuary = this.getAllKnownIds();

      // Announced public key is hashed in the packet, provide clear in the future (on seek)

      annuary[packet.getSenderHex()] = null;
      ShelterUtils.write(this.annuaryPath, annuary);
    });
  }

  /**
   * Initialize UDP socket, load or generate keys, and emit 'ready'
   */
  async init() {
    this.socket = await udpSocket({
      port: this.PORT,
      binaryType: "uint8array",
      hostname: "::", // ipv6 makes the client expose to global internet
      socket: {
        data: (_, data, port, address) => {
          this.emit("message", data, port, address);
        },
        error: (_, error) => {
          this.logger.error("Socket error:", error);
        },
      },
    });

    this.socket.setBroadcast(true);

    this.logger.log(`Listening on port ${this.PORT}`);

    let data = this.data.get();
    if (!data) {
      // Create keys if not existing.
      const keyPair = nacl.box.keyPair();

      data = {
        publicKey: ShelterUtils.toHex(keyPair.publicKey),
        secretKey: ShelterUtils.toHex(keyPair.secretKey),
      };

      this.data.set(data);
    }

    this.emit("ready", this);
  }

  get hashKey() {
    return blake3(ShelterUtils.fromHex(this.publicKey));
  }

  /**
   * Listen for SEEK packets and handle incoming connection requests
   */
  listenForSeeks() {
    this.on("message", (data: Uint8Array, port: number, address: string) => {
      const packet = new ShelterPacket(data);

      if (packet.getType() !== ShelterPacketType.SEEK) return;

      this.logger.log(`Received SEEK from ${packet.getSenderHex()}.`);

      if (Buffer.from(packet.getTarget()).equals(Buffer.from(this.hashKey))) {
        this.emit("call", packet.getSenderHex(), () => {
          // Accept callback executed, send SEEK_BACK
          // Respond with clear public key

          const p = ShelterPacket.build(69)
            .setType(ShelterPacketType.SEEK_BACK)
            .setSender(this.hashKey)
            .setTarget(packet.getSender())
            .build();

          this.socket.send(p.contents, port, address);
          this.logger.log(`Responded to SEEK from ${packet.getSenderHex()}.`);
        });

        /* this.socket.send(packet, port, address);

        this.logger.log(
          `Handshake initiated with __redacted-ip__ (${ShelterUtils.toHex(targetIdHash)}).`,
        );*/
      }
    });
  }

  /**
   * Broadcast an announce packet to the network
   */
  announce() {
    const packet = ShelterPacket.build(37)
      .setType(ShelterPacketType.ANNOUNCE)
      .setSender(blake3(ShelterUtils.fromHex(this.publicKey)))
      .build();

    let isSent = this.socket.send(
      packet.contents,
      this.PORT,
      "255.255.255.255",
    );

    if (!isSent) {
      this.logger.error("Failed to send announce packet");
      return;
    }

    this.logger.log("Sent announce packet to Shelter Network");
  }

  /**
   * Broadcast a seek packet to find a client by its public key hash.
   * @param targetPkHash
   * @returns
   */

  /**
   * Broadcast a seek packet to find a client by public key hash
   */
  seek(target: string) {
    // Seek packet length = 4 (magic) + 1 (type) + 32 (sender hash) + 32 (target hash)
    const packet = ShelterPacket.build(69)
      .setType(ShelterPacketType.SEEK)
      .setSender(blake3(ShelterUtils.fromHex(this.publicKey)))
      .setTarget(ShelterUtils.fromHex(target))
      .build();

    let isSent = this.socket.send(
      packet.contents,
      this.PORT,
      "255.255.255.255",
    );

    if (!isSent) {
      this.logger.error("Failed to send seek packet");
      return;
    }

    this.logger.log("Sent seek packet to Shelter Network");
  }

  /**
   * Create a conversation object for sending and receiving messages
   */
  createConversation(port: number, address: string, targetPkHash: Uint8Array) {
    return {
      send: (message: string) => {
        // a message packet is MAGIC(4) + Type(1) + sID(32) + dID(32) + Nonce(24) + Data(n)

        const { nonce, encrypted } = ShelterUtils.encrypt(
          ShelterUtils.fromHex(this.secretKey),
          Uint8Array.from(new TextEncoder().encode(message)),
          ShelterUtils.fromHex(
            this.getPublicKey(ShelterUtils.toHex(targetPkHash))!,
          ),
          this,
        );

        const packet = ShelterPacket.build(93 + encrypted.length)
          .setType(ShelterPacketType.MESSAGE)
          .setSender(this.hashKey)
          .setTarget(targetPkHash)
          .setNonce(nonce)
          .setEncryptedMessage(encrypted)
          .build();

        this.socket.send(packet.contents, port, address);
        this.logger.log(
          `Encrypted message sent to ${ShelterUtils.toHex(targetPkHash)}.`,
        );
      },
      onMessage: (cb: (msg: string, senderPubKey: Uint8Array) => void) => {
        this.on("text", (sender: string, msg: string) => {
          cb(msg, ShelterUtils.fromHex(sender));
        });
      },
    };
  }

  get hashKeyHex() {
    return ShelterUtils.toHex(this.hashKey);
  }

  /**
   * Listen for SEEK_BACK responses and establish links
   */
  listenForSeekResponse() {
    this.on(
      "message",
      async (data: Uint8Array, port: number, address: string) => {
        let packet = new ShelterPacket(data);

        if (packet.getType() !== ShelterPacketType.SEEK_BACK) return;

        // Data contains the public key of the responder in clear, not hashed
        // So we can store directly it in the annuary

        const hashedSenderHex = packet.hashSenderHex();

        let annuary = this.getAllKnownIds();
        annuary[hashedSenderHex] = packet.getSenderHex();

        ShelterUtils.write(this.annuaryPath, annuary);

        this.logger.log(
          `Client responded: SEEK_BACK message from ${hashedSenderHex}.`,
        );

        this.emit("link", hashedSenderHex, () => {
          return this.createConversation(port, address, packet.getSender());
        });
      },
    );
  }

  /**
   * Close the UDP socket
   */
  stop() {
    this.socket.close();
  }

  /**
   * Decrypt an incoming message packet
   */
  decrypt(packet: Uint8Array): string | null {
    let shelterPacket = new ShelterPacket(packet);
    let info = shelterPacket.getInfo();

    // In info, sender is Uint8Array (public key) took right from the packet;
    // It's usually found hashed.

    let { sender, encryptedMessage, nonce } = info;

    const secretKeyHex = ShelterUtils.fromHex(this.secretKey);

    const decrypted = nacl.box.open(
      encryptedMessage!,
      nonce!,
      ShelterUtils.fromHex(shelterPacket.getClearKey(this.getAllKnownIds())!),
      secretKeyHex,
    );

    if (!decrypted) {
      this.logger.error("Decryption failed (corrupted key or wrong recipient)");
      return null;
    }

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Get the public key from annuary by hash
   */
  getPublicKey(publicKeyHash: string): string | null {
    let annuary = this.getAllKnownIds();
    // Hash is value

    const keys = Object.keys(annuary);

    for (let key of keys) {
      if (annuary[key] === publicKeyHash) {
        return key;
      }
    }

    return null;
  }

  /**
   * Get all known IDs from the annuary file
   */
  getAllKnownIds(): { [key: string]: string | null } {
    let annuary: any = {};
    try {
      annuary = JSON.parse(readFileSync(this.annuaryPath, "utf-8"));
    } catch {
      return {};
    }

    return annuary;
  }
}
