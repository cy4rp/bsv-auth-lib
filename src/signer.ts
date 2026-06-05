/**
 * BSV message signing and verification.
 *
 * Implements Bitcoin Signed Message format:
 *   SHA256(SHA256("Bitcoin Signed Message:\n" + varint(len) + message))
 *
 * This is the same format used by BSV for `signmessage` / `verifymessage`.
 */
import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, derivePublicKey } from "./keys.js";

const MESSAGE_PREFIX = "Bitcoin Signed Message:\n";

/** Encode an integer as a Bitcoin varint */
function encodeVarint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    return buf;
  }
  throw new Error("Message too long for varint encoding");
}

/** Compute the double-SHA256 message hash used by Bitcoin Signed Message */
export function messageHash(message: string): Uint8Array {
  const prefixBytes = new TextEncoder().encode(MESSAGE_PREFIX);
  const messageBytes = new TextEncoder().encode(message);
  const prefixVarint = encodeVarint(prefixBytes.length);
  const messageVarint = encodeVarint(messageBytes.length);

  const buf = new Uint8Array(
    prefixVarint.length +
      prefixBytes.length +
      messageVarint.length +
      messageBytes.length,
  );
  let offset = 0;
  buf.set(prefixVarint, offset);
  offset += prefixVarint.length;
  buf.set(prefixBytes, offset);
  offset += prefixBytes.length;
  buf.set(messageVarint, offset);
  offset += messageVarint.length;
  buf.set(messageBytes, offset);

  return sha256(sha256(buf));
}

/** Sign a message with a BSV private key, returning a compact signature (hex) */
export async function signMessage(
  privateKey: Uint8Array,
  message: string,
): Promise<string> {
  const hash = messageHash(message);
  const sig = await secp.signAsync(hash, privateKey, { lowS: true });
  return bytesToHex(sig.toCompactRawBytes());
}

/** Verify a compact signature against a message and compressed public key (all hex) */
export function verifyMessage(
  signatureHex: string,
  message: string,
  publicKeyHex: string,
): boolean {
  try {
    const hash = messageHash(message);
    const sigBytes = hexToBytes(signatureHex);
    const sig = secp.Signature.fromCompact(sigBytes);
    const pubBytes = hexToBytes(publicKeyHex);
    return secp.verify(sig, hash, pubBytes);
  } catch {
    return false;
  }
}

/** Generate a random challenge string for authentication */
export function generateChallenge(prefix = "bsv-auth"): string {
  const randomBytes = new Uint8Array(32);
  if (typeof globalThis.crypto !== "undefined") {
    globalThis.crypto.getRandomValues(randomBytes);
  } else {
    // Node.js fallback
    for (let i = 0; i < 32; i++) {
      randomBytes[i] = Math.floor(Math.random() * 256);
    }
  }
  const timestamp = Date.now();
  return `${prefix}:${timestamp}:${bytesToHex(randomBytes)}`;
}

/** Create a signed authentication proof */
export async function createAuthProof(
  privateKey: Uint8Array,
  challenge: string,
): Promise<{ signature: string; publicKey: string }> {
  const signature = await signMessage(privateKey, challenge);
  const publicKey = bytesToHex(derivePublicKey(privateKey));
  return { signature, publicKey };
}
