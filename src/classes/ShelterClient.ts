import { blake3 } from "@noble/hashes/blake3.js";
import nacl from "tweetnacl";
import { readFileSync, writeFileSync } from "fs";
import { cwd } from "process";
import path from "path";
import { udpSocket, type udp } from "bun";
import EventEmitter from "events";
import Logger from "./Logger";

// ShelterClient is both a client and a server
enum ShelterPacketType {
  ANNOUNCE = 0x01,
  MESSAGE = 0x02,
  SEEK = 0x03,
  SEEK_BACK = 0x04,
}

interface ShelterClientOptions {
  datafilePath?: string;
  annuaryPath?: string;
  debug?: boolean;
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
    get: () => {
      try {
        const filepath = readFileSync(this.datafilePath, "utf-8");
        return JSON.parse(filepath);
      } catch {
        return null;
      }
    },
    set: (data: any) => {
      writeFileSync(this.datafilePath, JSON.stringify(data, null, 2), "utf-8");
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

      this.onAnnouncement((pubKey: Uint8Array) => {
        this.logger.log(
          `Received announcement from ${Buffer.from(pubKey).toString("hex")}`,
        );

        // Save to annuary
        let annuary: any = {};
        try {
          const filepath = readFileSync(this.annuaryPath, "utf-8");
          annuary = JSON.parse(filepath);
        } catch {
          annuary = {};
        }

        const idHex = Buffer.from(blake3(pubKey)).toString("hex");

        // Stocke les deux !
        annuary[idHex] = {
          publicKey: Array.from(pubKey), // Facile à relire pour toUint8
          lastSeen: new Date().toISOString(),
        };

        writeFileSync(
          this.annuaryPath,
          JSON.stringify(annuary, null, 2),
          "utf-8",
        );
      });
    });

    this.on("message", (data: Uint8Array) => {
      if (data[4] === ShelterPacketType.MESSAGE) {
        const clearText = this.decrypt(data);
        if (clearText) {
          this.logger.log(`Received message : ${clearText}`);
          this.emit("chat", clearText);
        }
      }
    });
  }

  onAnnouncement(cb: (pubKey: Uint8Array) => void) {
    this.on("message", (data: Uint8Array, port: number, address: string) => {
      if (data[4] !== ShelterPacketType.ANNOUNCE) return;

      let senderPubKey = data.slice(37, 69); // PK is at offset 37, length 32

      cb(senderPubKey);
    });
  }

  encrypt(message: string, destPubKey: Uint8Array) {
    // 1. Générer un nonce UNIQUE et ALÉATOIRE
    const nonce = nacl.randomBytes(24);
    const msgBytes = new TextEncoder().encode(message);

    // 2. Chiffrer
    const encrypted = nacl.box(
      msgBytes,
      nonce,
      destPubKey, // La clé publique de celui qui va RECEVOIR
      this.data.get().secretKey, // TA clé privée
    );

    return { nonce, encrypted };

    // Nonce is 24 bytes
    // Encrypted message follows
  }

  build(
    type: ShelterPacketType,
    message?: Uint8Array,
    targetKey?: Uint8Array,
    hashTarget: boolean = true,
  ): Uint8Array {
    const myData = this.data.get();
    const myPubKey = ShelterClient.toUint8(myData.publicKey);
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
      const { encrypted, nonce } = this.encrypt(
        Buffer.from(message).toString("utf-8"),
        targetKey,
      );
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

  static toUint8(data: any): Uint8Array {
    if (data instanceof Uint8Array) return data;
    if (typeof data === "string")
      return new Uint8Array(data.split(",").map(Number));
    return Uint8Array.from(Object.values(data));
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
        publicKey: keyPair.publicKey.toString(),
        secretKey: keyPair.secretKey.toString(),
      };

      this.data.set(data);
    }

    this.emit("ready");

    this.on("message", (data: Uint8Array, port: number, address: string) => {
      if (data[4] !== ShelterPacketType.SEEK) return;

      const targetIdHash = data.slice(37, 69);
      const myPubKey = ShelterClient.toUint8(this.data.get().publicKey);
      const myIdHash = blake3(myPubKey);

      if (Buffer.from(targetIdHash).equals(Buffer.from(myIdHash))) {
        // On récupère la PK de celui qui nous cherche (offset 5-37)
        const senderIdHash = data.slice(5, 37);

        const seekBack = this.build(
          ShelterPacketType.SEEK_BACK,
          undefined,
          senderIdHash,
          false,
        );

        this.socket.send(seekBack, port, address);

        this.logger.log(
          `Handshake initiated with __redacted-ip__ (${new TextDecoder("utf-8").decode(targetIdHash)})`,
        );
      }
    });
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

  seekFor(targetPubKey: Uint8Array) {
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
        // On accepte une string pour plus de confort
        const annuary = JSON.parse(readFileSync(this.annuaryPath, "utf-8"));
        const sidHex = Buffer.from(targetIdHash).toString("hex");

        // On récupère la vraie clé publique dans l'annuaire
        const targetPubKey = ShelterClient.toUint8(annuary[sidHex].publicKey);

        const packet = this.build(
          ShelterPacketType.MESSAGE,
          new TextEncoder().encode(message),
          targetPubKey,
          false, // On ne re-hashe pas, build() s'en occupera
        );

        this.socket.send(packet, port, address);
        this.logger.log(`Encrypted message sent to ${address}`);
      },
    };
  }

  onHandshake(
    cb: (r: ReturnType<typeof this.createConversation>) => void | Promise<void>,
  ) {
    this.on(
      "message",
      async (data: Uint8Array, port: number, address: string) => {
        if (data[4] !== ShelterPacketType.SEEK_BACK) return;

        const targetIdHash = data.slice(37, 69);
        const myPubKey = ShelterClient.toUint8(this.data.get().publicKey);
        const myIdHash = blake3(myPubKey);

        if (Buffer.from(targetIdHash).equals(Buffer.from(myIdHash))) {
          // On récupère la PK de celui qui nous a cherché (offset 5-37)
          const senderIdHash = data.slice(5, 37);

          this.logger.log(
            `Handshake received from __redacted-ip__ (${new TextDecoder("utf-8").decode(targetIdHash)}). You can now communicate.`,
          );

          this.emit("handshake", {
            address,
            port,
            senderIdHash,
          });

          await cb(this.createConversation(port, address, senderIdHash));
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
    const sID = packet.slice(5, 37);
    const sIDHex = Buffer.from(sID).toString("hex");

    let annuary: any = {};
    try {
      annuary = JSON.parse(readFileSync(this.annuaryPath, "utf-8"));
    } catch {
      return null;
    }

    const senderPubKeyRaw = annuary[sIDHex]?.publicKey;
    if (!senderPubKeyRaw) {
      this.logger.error("Unknown public key for this ID. Unable to decrypt.");
      return null;
    }

    const senderPubKey = ShelterClient.toUint8(senderPubKeyRaw);
    const nonce = packet.slice(69, 93);
    const encryptedData = packet.slice(93);
    const mySecretKey = ShelterClient.toUint8(this.data.get().secretKey);

    // 2. Ouvrir la boîte
    const decrypted = nacl.box.open(
      encryptedData,
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
}
