declare module "libsodium-wrappers" {
  export const ready: Promise<void>;
  export function crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
}
