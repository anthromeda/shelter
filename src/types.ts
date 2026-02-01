export type ShelterConversation = {
  send: (message: string) => void | Promise<void>;
  onMessage: (
    cb: (msg: string, senderPubKey: Uint8Array) => void | Promise<void>,
  ) => void | Promise<void>;
};

export interface ShelterData {
  publicKey: string; // hex
  secretKey: string; // hex
}
