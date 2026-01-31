import ShelterClient from "./classes/ShelterClient";

const client = new ShelterClient();

client.onReady(() => {
  client.seekFor(ShelterClient.toUint8(client.data.get().publicKey));

  client.onHandshake((conversation) => {});
});
