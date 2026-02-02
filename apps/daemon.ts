import ShelterClient from "../src";

const client = new ShelterClient();
const daemonApi = await client.exposeDaemonApi();
const port = daemonApi.port;
const host = daemonApi.address.address;

console.log(`Daemon API is running at ${host}:${port} (udp)`);
