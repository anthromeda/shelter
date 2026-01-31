import ShelterClient from "./classes/ShelterClient";
import { ShelterUtils } from "./classes/ShelterUtils";

const client = new ShelterClient({ debug: true });

client.onReady(() => {
  client.seekFor(ShelterUtils.toUint8(client.data.get().publicKey));

  client.onHandshake((sender, accept) => {
    // For now, we auto-accept all handshakes

    const conversation = accept();

    conversation.onMessage((message, sender) => {
      console.log(`${sender}: ${message}`);
    });
  });
});
