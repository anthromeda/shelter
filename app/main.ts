import ShelterClient from "../src/ShelterClient";
import { TerminalUI } from "./TerminalUI";

const activeConversations = new Set<any>();

const client = new ShelterClient({ debug: true });

// Initialize terminal UI and send input to all active conversations
const ui = new TerminalUI((line) => {
  // This runs when you press Enter
  for (const conv of activeConversations) {
    conv.send(line);
  }
});

// Handle client ready event and incoming connections
client.on("ready", () => {
  ui.log("LOG: Shelter Client is ready.");

  /**
   * Announce ourselves to the Shelter Network
   * Always ask for a hashed public key when trying to connect to someone
   */
  client.seek(client.hashKeyHex);

  // Handle incoming call requests
  client.on("call", (sender, accept) => {
    // Someones shouted a SEEK packet that targets us
    accept(); // This sends a SEEK_BACK packet automatically
  });

  // Handle successful link and add conversation
  client.on("link", (sender, accept) => {
    const conv = accept(); // Creates a conversation object
    activeConversations.add(conv);
  });
});
