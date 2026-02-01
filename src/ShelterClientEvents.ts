import type ShelterClient from "./ShelterClient";
import { ShelterConversation } from "./types";

type ShelterClientEvents = {
  ready: [client: ShelterClient];
  announcement: [senderPkHashHex: string];
  text: [senderPkHashHex: string, message: string];
  call: [senderPkHashHex: string, accept: () => void | Promise<void>];
  link: [
    senderPkHashHex: string,
    accept: () => ShelterConversation | Promise<ShelterConversation>,
  ];
};

export default ShelterClientEvents;
