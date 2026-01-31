export class ShelterUtils {
  static toUint8(data: any): Uint8Array {
    if (data instanceof Uint8Array) return data;
    if (typeof data === "string")
      return new Uint8Array(data.split(",").map(Number));
    return Uint8Array.from(Object.values(data));
  }
}
