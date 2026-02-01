import { readFileSync, writeFileSync } from "fs";
import ShelterClient from "./ShelterClient";
import { blake3 } from "@noble/hashes/blake3.js";
import { ShelterPacketType } from "./ShelterPacketType";
import nacl from "tweetnacl";

export class ShelterUtils {
  static toHex(uint8array: Uint8Array): string {
    return Buffer.from(uint8array).toString("hex");
  }

  static fromHex(hexString: string) {
    return Buffer.from(hexString, "hex");
  }

  static read<T>(path: string): T | null {
    try {
      return JSON.parse(readFileSync(path, "utf-8")) as T;
    } catch {
      return null;
    }
  }

  static write<T>(path: string, data: T): void {
    writeFileSync(path, JSON.stringify(data, null, 2), "utf-8");
  }

  private static encrypt(
    secretKey: Uint8Array,
    msgBytes: Uint8Array,
    destPubKey: Uint8Array,
    client: ShelterClient,
  ) {
    const nonce = nacl.randomBytes(24);

    // DestPubKey is hash!!! Get real pubkey before using

    // let clearPubKey = client.getPublicKey(ShelterUtils.toHex(destPubKey))!;
    // const destPubKeyBytes = ShelterUtils.fromHex(clearPubKey);

    const encrypted = nacl.box(msgBytes, nonce, destPubKey, secretKey);

    return { nonce, encrypted };
  }

  static createMessagePacket(options: {
    message: Uint8Array;
    client: ShelterClient;
    targetPkHash: Uint8Array;
    doHash?: boolean;
  }): Uint8Array {
    const { message, client, targetPkHash } = options;

    const targetPk = client.getPublicKey(ShelterUtils.toHex(targetPkHash));

    const { encrypted, nonce } = this.encrypt(
      ShelterUtils.fromHex(client.secretKey),
      message,
      ShelterUtils.fromHex(targetPk!),
      client,
    );

    const myPubKey = ShelterUtils.fromHex(client.publicKey);

    // Magic(4) + Type(1) + sID(32) + dID(32) + Nonce(24) + Data(n)
    const packet = new Uint8Array(93 + encrypted.length);
    packet.set(Buffer.from(client.intrinsic.MAGIC), 0);
    packet[4] = ShelterPacketType.MESSAGE;
    packet.set(myPubKey, 5);
    packet.set(targetPkHash, 37);
    packet.set(nonce, 69);
    packet.set(encrypted, 93);
    return packet;
  }

  static createAnnouncePacket(options: { client: ShelterClient }): Uint8Array {
    const { client } = options;

    const myPubKey = ShelterUtils.fromHex(client.publicKey);
    const sID = blake3(myPubKey);

    // Magic(4) + Type(1) + sID(32)
    const packet = new Uint8Array(37);

    packet.set(Buffer.from(client.intrinsic.MAGIC), 0);
    packet[4] = ShelterPacketType.ANNOUNCE;
    packet.set(sID, 5);

    return packet;
  }

  static createSeekPacket(options: {
    client: ShelterClient;
    targetPk: Uint8Array;
  }): Uint8Array {
    const { client, targetPk } = options;

    const myPubKey = ShelterUtils.fromHex(client.publicKey);
    const myPkHash = blake3(myPubKey);

    // Magic(4) + Type(1) + sID(32) + dID(32)
    const packet = new Uint8Array(69);

    packet.set(Buffer.from(client.intrinsic.MAGIC), 0);
    packet[4] = ShelterPacketType.SEEK;
    packet.set(myPkHash, 5);
    packet.set(blake3(targetPk), 37);

    return packet;
  }

  // Packet, containing clear sender public key for unicast message
  static createSeekBackPacket(options: { client: ShelterClient }): Uint8Array {
    const { client } = options;

    const myPubKey = ShelterUtils.fromHex(client.publicKey);

    // No hash

    // Magic(4) + Type(1) + sID(32)
    const packet = new Uint8Array(37);

    packet.set(Buffer.from(client.intrinsic.MAGIC), 0);
    packet[4] = ShelterPacketType.SEEK_BACK;
    packet.set(myPubKey, 5);

    return packet;
  }
}
