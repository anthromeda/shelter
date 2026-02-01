import { readFileSync, writeFileSync } from "fs";

export class ShelterUtils {
  static toHex(uint8array: Uint8Array): string {
    return Buffer.from(uint8array).toHex();
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
}
