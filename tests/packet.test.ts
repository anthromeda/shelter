import { describe, it, expect } from "vitest";
import ShelterPacket from "../src/ShelterPacket";
import { ShelterPacketType } from "../src/ShelterPacketType";

describe("ShelterPacket", () => {
  it("should build a packet and get correct type and sender", () => {
    ShelterPacket.setMagic("MAGC");
    const type = ShelterPacketType.ANNOUNCE || 1;
    const sender = new Uint8Array(32).fill(1); // 32 bytes
    const target = new Uint8Array(32).fill(2); // 32 bytes
    const nonce = new Uint8Array(24).fill(3); // 24 bytes
    const encryptedMessage = new Uint8Array(10).fill(4); // 10 bytes

    const packet = ShelterPacket.build(103)
      .setType(type)
      .setSender(sender)
      .setTarget(target)
      .setNonce(nonce)
      .setEncryptedMessage(encryptedMessage)
      .build();

    expect(packet.getType()).toBe(type);
    expect(packet.getSender()).toEqual(sender);
    expect(packet.getTarget()).toEqual(target);
    expect(packet.getNonce()).toEqual(nonce);
    expect(packet.getEncryptedMessage()).toEqual(encryptedMessage);
  });

  it("should return correct info from getInfo", () => {
    ShelterPacket.setMagic("MAGC");
    const type = ShelterPacketType.ANNOUNCE || 1;
    const sender = new Uint8Array(32).fill(5);
    const target = new Uint8Array(32).fill(6);
    const nonce = new Uint8Array(24).fill(7);
    const encryptedMessage = new Uint8Array(10).fill(8);

    const packet = ShelterPacket.build(103)
      .setType(type)
      .setSender(sender)
      .setTarget(target)
      .setNonce(nonce)
      .setEncryptedMessage(encryptedMessage)
      .build();

    const info = packet.getInfo();
    expect(info.type).toBe(type);
    expect(info.sender).toEqual(sender);
    expect(info.target).toEqual(target);
    expect(info.nonce).toEqual(nonce);
    expect(info.encryptedMessage).toEqual(encryptedMessage);
  });
});
