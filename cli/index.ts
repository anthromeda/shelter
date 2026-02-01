import {
  createCommand,
  createArgument,
  createOption,
  Command,
} from "commander";

import ShelterClient from "../dist/bundle";
import { blake3 } from "@noble/hashes/blake3.js";

let debugMode = false;

const program = new Command();

program.helpCommand(true);

program
  .name("shelter-cli")
  .description("CLI for Shelter Encrypted Chat Client")
  .version("1.0.0")
  .option("-d, --debug", "enable debug mode")
  .option("-t, --target <publicKey>", "target public key to connect to");

if (program.parse) program.parse(process.argv);

const options = program.opts();
const args = program.args;

console.log("Options:", options);
console.log("Arguments:", args);

if (options.debug) debugMode = true;
const client = new ShelterClient({ debug: debugMode });

client.logger.log("Creating Shelter Client...");

client.onReady(() => {
  client.logger.log("You are now connected to the Shelter network.");
  // client.logger.log(`Your public key: ${client.getPublicKeyHex()}`);

  if (options.target) {
    // Target is a hex string of the public key
    // Convert hex string to Uint8Array

    client.seekFor(Uint8Array.from(Buffer.from(options.target, "hex"))); // Broadcast seek request

    client.onHandshake(async (senderIdHash: Uint8Array, accept: any) => {
      client.logger.log(
        `Handshake established with target (${options.target}). You can now communicate.`,
      );
      // Now you can communicate with the target
    });
  }
});
