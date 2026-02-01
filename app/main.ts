import { blake3 } from "@noble/hashes/blake3.js";
import ShelterClient from "../src/ShelterClient";
import { ShelterUtils } from "../src/ShelterUtils";
import { TerminalUI } from "./TerminalUI";

const activeConversations = new Set<any>();

const client = new ShelterClient({ debug: true });

const ui = new TerminalUI((line) => {
  // This runs when you press Enter
  for (const conv of activeConversations) {
    conv.send(line);
  }
});

client.on("ready", () => {
  ui.log("LOG: Shelter Client is ready.");

  console.log(client.publicKey);

  /**
   * Announce ourselves to the Shelter Network
   * Always ask for a hashed public key when trying to connect to someone
   */
  client.seek(client.publicKey);

  client.on("call", (sender, accept) => {
    ui.log(`Incoming call from ${sender}`);
    // Someones shouted a SEEK packet that targets us
    accept(); // This sends a SEEK_BACK packet automatically
  });

  client.on("link", (sender, accept) => {
    const conv = accept();
    ui.log(`LOG: Linked with ${sender}`);
    activeConversations.add(conv);
  });
});
