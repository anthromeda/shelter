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

// ShelterClient is both a client and a server

interface ShelterData {
  publicKey: string; // hex
  secretKey: string; // hex
}

export default class ShelterClient extends EventEmitter.EventEmitter {
  private socket!: udp.Socket<"uint8array">;
  private PORT: number = 4444;

  private _intrinsic = {
    MAGIC: "SHR1",
  };

  private logger: Logger;

  get intrinsic() {
    return this._intrinsic;
  }

  public readonly data = {
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

    (async () => {
      await this.init();
    })();

    this.onReady(() => {
      this.announce();

      this.onAnnouncement(async (pubKey: Uint8Array) => {
        let senderHex = ShelterUtils.toHex(pubKey);
        this.logger.log(`Received announcement from ${senderHex}`);

        // Save to annuary
        let annuary = this.getAllKnownIds();

        const idHex = ShelterUtils.toHex(blake3(pubKey));

        // Stocke les deux !
        annuary[idHex] = {
          publicKey: ShelterUtils.toHex(pubKey),
        };

        ShelterUtils.write(this.annuaryPath, annuary);
      });
    });

    this.on("message", async (data: Uint8Array) => {
      let info = this.getInfoFromPacket(data);
      if (info.type === ShelterPacketType.MESSAGE) {
        const clearText = this.decrypt(data);

        if (clearText) {
          this.logger.log(`Received message : ${clearText}`);
          this.emit("chat", clearText, info.senderPubKey);
        }
      }
    });
  }

  onAnnouncement(cb: (pubKey: Uint8Array) => Promise<void> | void) {
    this.on(
      "message",
      async (data: Uint8Array, port: number, address: string) => {
        let info = this.getInfoFromPacket(data);
        if (info.type !== ShelterPacketType.ANNOUNCE) return;
        await cb(info.senderPubKey);
      },
    );
  }

  encrypt(msgBytes: Uint8Array, destPubKey: Uint8Array) {
    const nonce = nacl.randomBytes(24);
    const mySecretKey = ShelterUtils.fromHex(this.data.get()!.secretKey);

    const encrypted = nacl.box(msgBytes, nonce, destPubKey, mySecretKey);

    return { nonce, encrypted };
  }

  build(
    type: ShelterPacketType,
    message?: Uint8Array,
    targetKey?: Uint8Array,
    hashTarget: boolean = true,
  ): Uint8Array {
    const myData = this.data.get();
    const myPubKey = ShelterUtils.fromHex(myData!.publicKey);
    const sID = blake3(myPubKey);

    if (type === ShelterPacketType.ANNOUNCE) {
      const totalSize = 5 + sID.length + myPubKey.length; // 4 + 1 + 32 + 32 = 69
      const packet = new Uint8Array(totalSize);

      packet.set(Buffer.from(this._intrinsic.MAGIC), 0);
      packet[4] = type;
      packet.set(sID, 5);
      packet.set(myPubKey, 5 + sID.length); // Utilise la longueur dynamique

      return packet;
    }

    if (type === ShelterPacketType.MESSAGE && message && targetKey) {
      const { encrypted, nonce } = this.encrypt(message, targetKey);
      const dID = blake3(targetKey);

      // Magic(4) + Type(1) + sID(32) + dID(32) + Nonce(24) + Data(n)
      const packet = new Uint8Array(93 + encrypted.length);
      packet.set(Buffer.from(this._intrinsic.MAGIC), 0);
      packet[4] = type;
      packet.set(sID, 5);
      packet.set(dID, 37);
      packet.set(nonce, 69);
      packet.set(encrypted, 93);
      return packet;
    }

    if (type === ShelterPacketType.SEEK && targetKey) {
      const dID = hashTarget ? blake3(targetKey) : targetKey;

      // Magic(4) + Type(1) + sID(32) + dID(32)
      const packet = new Uint8Array(69);
      packet.set(Buffer.from(this._intrinsic.MAGIC), 0);
      packet[4] = type;
      packet.set(sID, 5);
      packet.set(dID, 37);
      return packet;
    }

    if (type === ShelterPacketType.SEEK_BACK && targetKey) {
      const dID = hashTarget ? blake3(targetKey) : targetKey;

      // Magic(4) + Type(1) + sID(32) + dID(32)
      const packet = new Uint8Array(69);
      packet.set(Buffer.from(this._intrinsic.MAGIC), 0);
      packet[4] = type;
      packet.set(sID, 5);
      packet.set(dID, 37);
      return packet;
    }
    throw new Error("Invalid packet build parameters");
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

    this.emit("ready");

    this.on("message", (data: Uint8Array, port: number, address: string) => {
      let info = this.getInfoFromPacket(data);

      if (info.type !== ShelterPacketType.SEEK) return;

      let { targetIdHash, myIdHash, senderIdHash } = info;

      if (Buffer.from(targetIdHash).equals(Buffer.from(myIdHash))) {
        const seekBack = this.build(
          ShelterPacketType.SEEK_BACK,
          undefined,
          senderIdHash,
          false,
        );

        this.socket.send(seekBack, port, address);

        const targetPubKeyHex = this.getPkByIdHash(
          ShelterUtils.toHex(senderIdHash),
        )!;

        this.logger.log(
          `Handshake initiated with __redacted-ip__ (${targetPubKeyHex}).`,
        );
      }
    });
  }

  getInfoFromPacket(packet: Uint8Array): {
    targetIdHash: Uint8Array;
    senderIdHash: Uint8Array;
    senderPubKey: Uint8Array;
    myPubKey: Uint8Array;
    myIdHash: Uint8Array;
    senderIdHashHex: string;
    type: ShelterPacketType;
    nonce: Uint8Array;
    encryptedData?: Uint8Array;
  } {
    let x = {
      type: packet[4] as ShelterPacketType,
      senderIdHash: packet.slice(5, 37),
      targetIdHash: packet.slice(37, 69),
      myPubKey: ShelterUtils.fromHex(this.data.get()!.publicKey),
      nonce: packet.slice(69, 93),
      encryptedData: packet.slice(93),
    } as unknown as ReturnType<ShelterClient["getInfoFromPacket"]>;

    x.myIdHash = blake3(x.myPubKey);
    x.senderIdHashHex = ShelterUtils.toHex(x.senderIdHash);
    x.senderPubKey = ShelterUtils.fromHex(
      this.getPkByIdHash(x.senderIdHashHex)!,
    );

    return x;
  }

  announce() {
    const packet = this.build(ShelterPacketType.ANNOUNCE);
    let isSent = this.socket.send(packet, this.PORT, "255.255.255.255");

    if (!isSent) {
      this.logger.error("Failed to send announce packet");
      return;
    }

    this.logger.log("Sent announce packet to Shelter Network");
  }

  seekFor(targetPubKeyHex: string) {
    const targetPubKey = ShelterUtils.fromHex(targetPubKeyHex);
    const packet = this.build(ShelterPacketType.SEEK, undefined, targetPubKey);
    let isSent = this.socket.send(packet, this.PORT, "255.255.255.255");

    if (!isSent) {
      this.logger.error("Failed to send seek packet");
      return;
    }

    this.logger.log("Sent seek packet to Shelter Network");
  }

  createConversation(port: number, address: string, targetIdHash: Uint8Array) {
    return {
      send: (message: string) => {
        const knownIds = this.getAllKnownIds();
        const targetIdHex = ShelterUtils.toHex(targetIdHash);

        const targetPubKeyHex = knownIds[targetIdHex]!.publicKey;
        const targetPubKey = ShelterUtils.fromHex(targetPubKeyHex);

        const packet = this.build(
          ShelterPacketType.MESSAGE,
          Uint8Array.from(new TextEncoder().encode(message)),
          targetPubKey,
        );

        this.socket.send(packet, port, address);
        this.logger.log(
          `Encrypted message sent to __redacted-ip__ (${ShelterUtils.toHex(targetPubKey)}).`,
        );
      },
      onMessage: (cb: (msg: string, senderPubKey: Uint8Array) => void) => {
        this.on("chat", (msg: string, senderPubKeyHash: string) => {
          cb(msg, ShelterUtils.fromHex(senderPubKeyHash));
        });
      },
    };
  }

  onHandshake(
    cb: (
      senderPubKey: Uint8Array,
      accept: () => ReturnType<typeof this.createConversation>,
    ) => void | Promise<void>,
  ) {
    this.on(
      "message",
      async (data: Uint8Array, port: number, address: string) => {
        let info = this.getInfoFromPacket(data);
        if (info.type !== ShelterPacketType.SEEK_BACK) return;

        const { targetIdHash, myIdHash, senderPubKey } = info;

        if (Buffer.from(targetIdHash).equals(Buffer.from(myIdHash))) {
          const senderPkHex = ShelterUtils.toHex(senderPubKey);

          this.logger.log(
            `Handshake received from __redacted-ip__ (${senderPkHex!}). You can now communicate.`,
          );

          await cb(info.senderPubKey, () =>
            this.createConversation(port, address, info.senderIdHash),
          );
        }
      },
    );
  }

  onReady(callback: () => void | Promise<void>) {
    this.on("ready", callback);
  }

  stop() {
    this.socket.close();
  }

  decrypt(packet: Uint8Array): string | null {
    const info = this.getInfoFromPacket(packet);

    let { senderPubKey, encryptedData, nonce } = info;

    const mySecretKey = ShelterUtils.fromHex(this.data.get()!.secretKey);

    // 2. Ouvrir la boîte
    const decrypted = nacl.box.open(
      encryptedData!,
      nonce,
      senderPubKey,
      mySecretKey,
    );

    if (!decrypted) {
      this.logger.error("Decryption failed (corrupted key or wrong recipient)");
      return null;
    }

    return new TextDecoder().decode(decrypted);
  }

  getPkByIdHash(idHash: string): string | null {
    let annuary = this.getAllKnownIds();

    const pubKeyHex = annuary[idHash]?.publicKey;
    if (!pubKeyHex) {
      return null;
    }

    return pubKeyHex;
  }

  getAllKnownIds(): { [key: string]: { publicKey: string } } {
    let annuary: any = {};
    try {
      annuary = JSON.parse(readFileSync(this.annuaryPath, "utf-8"));
    } catch {
      return {};
    }

    return annuary;
  }
}
