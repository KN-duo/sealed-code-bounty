// prints the X25519 public key hex for a 32-byte scalar given as argv[2]
import sodium from "../cli/node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js";
await sodium.ready;
const sk = Uint8Array.from(Buffer.from(process.argv[2] ?? "", "hex"));
const pk = sodium.crypto_scalarmult_base(sk);
process.stdout.write(Buffer.from(pk).toString("hex"));
