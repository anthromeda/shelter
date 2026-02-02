import { Command } from "commander";

const program = new Command();

program
  .name("shelter-cli")
  .description("CLI for Shelter P2P client")
  .version("1.0.0");

const daemonPort = 4445;

const udpSocket = await Bun.udpSocket({
  port: 4446,
  binaryType: "uint8array",
  socket: {
    data(_, data) {
      const decoder = new TextDecoder();
      const message = decoder.decode(data);

      try {
        const json = JSON.parse(message);
        console.log(json);
        udpSocket.close();
      } catch {
        console.log(message);
        udpSocket.close();
      }
    },
  },
});

program.command("seek <publicKeyHash>").action((publicKeyHash) => {
  const encoder = new TextEncoder();
  const message = encoder.encode(`seek ${publicKeyHash}`);
  udpSocket.send(message, daemonPort, udpSocket.address.address);
});

program.command("messages").action(() => {
  const encoder = new TextEncoder();
  const message = encoder.encode("messages");
  udpSocket.send(message, daemonPort, udpSocket.address.address);
});

program.command("annuary").action(() => {
  const encoder = new TextEncoder();
  const message = encoder.encode("annuary");
  udpSocket.send(message, daemonPort, udpSocket.address.address);
});

program.command("public_key").action(() => {
  const encoder = new TextEncoder();
  const message = encoder.encode("getPublicKey");
  udpSocket.send(message, daemonPort, udpSocket.address.address);
});

program.command("accept <publicKeyHash>").action((publicKeyHash) => {
  const encoder = new TextEncoder();
  const message = encoder.encode(`accept ${publicKeyHash}`);
  udpSocket.send(message, daemonPort, udpSocket.address.address);
});

program
  .command("send <publicKeyHash> <message>")
  .action((publicKeyHash, message) => {
    const encoder = new TextEncoder();
    const fullMessage = encoder.encode(`send ${publicKeyHash} ${message}`);
    udpSocket.send(fullMessage, daemonPort, udpSocket.address.address);
  });

program.parse();
