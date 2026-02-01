import { describe, it, expect, vi, beforeEach } from "vitest";
import ShelterClient from "../src/ShelterClient";
import { ShelterClientOptions } from "../src/ShelterClientOptions";

describe("ShelterClient", () => {
  let client: ShelterClient;
  let options: ShelterClientOptions;

  beforeEach(() => {
    // Mock file system and UDP socket
    options = {
      datafilePath: "./mock_data.json",
      annuaryPath: "./mock_annuary.json",
      debug: true,
    };
    client = new ShelterClient(options);
    // Mock data.get/set
    client["data"].get = () => ({ publicKey: "abc", secretKey: "def" });
    client["data"].set = vi.fn();
  });

  it("should initialize with default options", () => {
    expect(client).toBeInstanceOf(ShelterClient);
    expect(client.intrinsic.MAGIC).toBe("SHR1");
  });

  it("should get public and secret keys from data", () => {
    expect(client.publicKey).toBe("abc");
    expect(client.secretKey).toBe("def");
  });

  it("should get and set annuary data", () => {
    // Mock ShelterUtils.write and read
    const annuary = { hash1: null };
    vi.spyOn(client, "getAllKnownIds").mockReturnValue(annuary);
    expect(client.getAllKnownIds()).toEqual(annuary);
  });

  it("should emit and handle events", () => {
    const spy = vi.fn();
    client.on("ready", spy);
    client.emit("ready", client);
    expect(spy).toHaveBeenCalled();
  });

  it("should return null for unknown public key hash", () => {
    vi.spyOn(client, "getAllKnownIds").mockReturnValue({});
    expect(client.getPublicKey("notfound")).toBeNull();
  });

  it("should stop the client (close socket)", () => {
    client["socket"] = { close: vi.fn() } as any;
    client.stop();
    expect(client["socket"].close).toHaveBeenCalled();
  });
});
