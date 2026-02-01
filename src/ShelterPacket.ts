import { blake3 } from "@noble/hashes/blake3.js";
import { ShelterPacketType } from "./ShelterPacketType";

export type PacketInfo = {
  type: ShelterPacketType;
  encryptedMessage: Uint8Array | null;
  nonce: Uint8Array | null;
  sender: Uint8Array;
  target: Uint8Array | null;
};

let globalMagic = "";

export default class ShelterPacket {
  constructor(private data: Uint8Array) {
    this.data = data;
  }

  static getMagic(): string {
    return globalMagic;
  }

  static setMagic(magic: string) {
    globalMagic = magic;
  }

  static build(length: number) {
    let b = new Uint8Array(length);

    b.set(Buffer.from(ShelterPacket.getMagic()), 0); // MAGIC

    let builder = {
      setType: (type: ShelterPacketType) => {
        // set type in data
        b[4] = type;
        return builder;
      },
      setSender: (sender: Uint8Array) => {
        b.set(sender, 5);
        return builder;
      },
      setTarget: (target: Uint8Array) => {
        b.set(target, 37);
        return builder;
      },
      setNonce: (nonce: Uint8Array) => {
        b.set(nonce, 69);
        return builder;
      },
      setEncryptedMessage: (encryptedMessage: Uint8Array) => {
        b.set(encryptedMessage, 93);
        return builder;
      },

      build: () => {
        return new ShelterPacket(b);
      },
    };

    return builder;
  }

  get contents(): Uint8Array {
    return this.data;
  }

  getInfo(): PacketInfo {
    // Announce packet have only type and sender

    return {
      type: this.getType(),
      sender: this.getSender(),
      nonce: this.getNonce(),
      target: this.getTarget(),
      encryptedMessage: this.getEncryptedMessage(),
    };
  }

  getType(): ShelterPacketType {
    return this.data[4] as ShelterPacketType;
  }

  getClearKey(annuary: { [key: string]: string | null }): string | null {
    const senderPk = Buffer.from(this.getSender()).toString("hex");

    const keys = Object.keys(annuary);

    for (let key of keys) {
      if (annuary[key] === senderPk) {
        return key;
      }
    }

    return null;
  }

  hashSender() {
    return blake3(this.getSender());
  }

  hashSenderHex() {
    return Buffer.from(this.hashSender()).toString("hex");
  }

  hashTarget() {
    return blake3(this.getTarget());
  }

  hashTargetHex() {
    return Buffer.from(this.hashTarget()).toString("hex");
  }

  getSender(): Uint8Array {
    return this.data.slice(5, 37);
  }

  getTarget(): Uint8Array {
    return this.data.slice(37, 69);
  }

  getEncryptedMessage(): Uint8Array {
    return this.data.slice(93);
  }

  getNonce(): Uint8Array | null {
    return this.data.slice(69, 93);
  }

  getSenderHex(): string {
    return Buffer.from(this.getSender()).toString("hex");
  }

  getTargetHex(): string {
    return Buffer.from(this.getTarget()).toString("hex");
  }

  getTargetHash(): Uint8Array {
    return blake3(this.getTarget());
  }
}
