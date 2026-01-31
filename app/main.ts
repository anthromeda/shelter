debugger;

import ShelterClient from "../src/classes/ShelterClient";
import { ShelterUtils } from "../src/classes/ShelterUtils";
import { TerminalUI } from "./TerminalUI";

const activeConversations = new Set<any>();

const client = new ShelterClient({ debug: true });

const ui = new TerminalUI((line) => {
  // This runs when you press Enter
  for (const conv of activeConversations) {
    conv.send(line);
  }
});

client.onReady(() => {
  ui.log("LOG: Shelter Client is ready.");

  client.seekFor(ShelterUtils.toUint8(client.data.get().publicKey)); // target ourself for now

  client.onHandshake(async (sender, accept) => {
    const conversation = accept();
    activeConversations.add(conversation);
    ui.log(
      `LOG: New handshake from ${Buffer.from(sender).toString("hex").substring(0, 8)}`,
    );
  });
});
