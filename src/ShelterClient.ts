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
import { ShelterConversation, ShelterData } from "./types";

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

  private openConversations = new Set<ShelterConversation>();

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

  get publicKey(): string {
    return this.data.get()!.publicKey;
  }

  get secretKey(): string {
    return this.data.get()!.secretKey;
  }

  private listenForMessages() {
    this.on("message", async (data: Uint8Array) => {
      let info = this.getInfoFromPacket(data);

      if (info.type === ShelterPacketType.MESSAGE) {
        const clearText = this.decrypt(data);

        if (!clearText) return;

        this.logger.log(`Received message : ${clearText}`);
        this.emit("text", info.senderPkHex, clearText);
      }
    });
  }

  private listenForAnnouncements() {
    this.on("message", async (data: Uint8Array) => {
      let info = this.getInfoFromPacket(data);
      if (info.type !== ShelterPacketType.ANNOUNCE) return;
      const pubKey = info.senderPubKey;

      let senderHex = ShelterUtils.toHex(pubKey);
      this.logger.log(`Received announcement from ${senderHex}`);

      // Save to annuary
      let annuary = this.getAllKnownIds();

      // Announced public key is hashed in the packet, provide clear in the future (on seek)

      annuary[senderHex] = null;
      ShelterUtils.write(this.annuaryPath, annuary);
    });
  }

  async init() {
    this.socket = await udpSocket({
      port: this.PORT,
      binaryType: "uint8array",
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

  listenForSeeks() {
    this.on("message", (data: Uint8Array, port: number, address: string) => {
      let info = this.getInfoFromPacket(data);

      if (info.type !== ShelterPacketType.SEEK) return;

      let { targetPubKey, myPkHash, senderPubKey } = info;

      let senderPkHex = this.getPublicKey(ShelterUtils.toHex(senderPubKey))!;

      this.logger.log(`Received SEEK from __redacted-ip__ (${senderPkHex}).`);

      if (Buffer.from(targetPubKey).equals(Buffer.from(myPkHash))) {
        this.emit("call", senderPkHex, () => {
          // Accept callback executed, send SEEK_BACK

          const packet = ShelterUtils.createSeekBackPacket({ client: this });

          this.socket.send(packet, port, address);

          this.logger.log(
            `Responded to SEEK from __redacted-ip__ (${ShelterUtils.toHex(senderPubKey)}).`,
          );
        });

        /* this.socket.send(packet, port, address);

        this.logger.log(
          `Handshake initiated with __redacted-ip__ (${ShelterUtils.toHex(targetIdHash)}).`,
        );*/
      }
    });
  }

  getInfoFromPacket(packet: Uint8Array): {
    targetPubKey: Uint8Array;
    senderPubKey: Uint8Array;
    myPubKey: Uint8Array;
    myPkHash: Uint8Array;
    senderPkHex: string;
    type: ShelterPacketType;
    nonce: Uint8Array;
    encryptedData?: Uint8Array;
  } {
    let x = {
      targetPubKey: packet.slice(37, 69),
      senderPubKey: packet.slice(5, 37),
      myPubKey: ShelterUtils.fromHex(this.publicKey),
      myPkHash: blake3(ShelterUtils.fromHex(this.publicKey)),
      senderPkHex: ShelterUtils.toHex(packet.slice(5, 37)),
      type: packet[4] as ShelterPacketType,
      nonce: packet.slice(69, 93),
      encryptedData: packet.slice(93),
    };

    return x;
  }

  announce() {
    const packet = ShelterUtils.createAnnouncePacket({ client: this });
    let isSent = this.socket.send(packet, this.PORT, "255.255.255.255");

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

  seek(targetPkHex: string) {
    const packet = ShelterUtils.createSeekPacket({
      client: this,
      targetPk: ShelterUtils.fromHex(targetPkHex),
    });

    let isSent = this.socket.send(packet, this.PORT, "255.255.255.255");

    if (!isSent) {
      this.logger.error("Failed to send seek packet");
      return;
    }

    this.logger.log("Sent seek packet to Shelter Network");
  }

  createConversation(port: number, address: string, targetPkHash: Uint8Array) {
    return {
      send: (message: string) => {
        console.log(targetPkHash);
        const packet = ShelterUtils.createMessagePacket({
          message: Uint8Array.from(new TextEncoder().encode(message)),
          client: this,
          targetPkHash,
        });
        this.socket.send(packet, port, address);
        this.logger.log(
          `Encrypted message sent to __redacted-ip__ (${ShelterUtils.toHex(targetPkHash)}).`,
        );
      },
      onMessage: (cb: (msg: string, senderPubKey: Uint8Array) => void) => {
        this.on("text", (senderPkHashHex: string, msg: string) => {
          cb(msg, ShelterUtils.fromHex(senderPkHashHex));
        });
      },
    };
  }

  listenForSeekResponse() {
    this.on(
      "message",
      async (data: Uint8Array, port: number, address: string) => {
        const info = this.getInfoFromPacket(data);
        if (info.type !== ShelterPacketType.SEEK_BACK) return;

        const { senderPubKey } = info;

        // A seek response has no target since it's unicasting back to us

        const senderPkHex = ShelterUtils.toHex(senderPubKey);

        // Data contains the public key of the responder in clear, not hashed
        // So we can store directly it in the annuary

        let annuary = this.getAllKnownIds();
        annuary[ShelterUtils.toHex(blake3(ShelterUtils.fromHex(senderPkHex)))] =
          ShelterUtils.toHex(senderPubKey);

        ShelterUtils.write(this.annuaryPath, annuary);

        this.logger.log(
          `Client responded: SEEK_BACK message from __redacted-ip__ (${senderPkHex}).`,
        );

        this.emit("link", senderPkHex, () => {
          return this.createConversation(port, address, senderPubKey);
        });
      },
    );
  }

  stop() {
    this.socket.close();
  }

  decrypt(packet: Uint8Array): string | null {
    const info = this.getInfoFromPacket(packet);

    let { senderPubKey, encryptedData, nonce } = info;

    const mySecretKey = ShelterUtils.fromHex(this.secretKey);

    const decrypted = nacl.box.open(
      encryptedData!,
      nonce,
      ShelterUtils.fromHex(
        this.getPublicKey(ShelterUtils.toHex(senderPubKey))!,
      ),
      mySecretKey,
    );

    if (!decrypted) {
      this.logger.error("Decryption failed (corrupted key or wrong recipient)");
      return null;
    }

    return new TextDecoder().decode(decrypted);
  }

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
