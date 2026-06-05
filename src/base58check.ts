/**
 * Base58Check encoding/decoding (Bitcoin-style).
 *
 * Uses @noble/hashes SHA-256 for the 4-byte checksum.
 * Zero-dependency alternative to bs58check (avoids CJS/ESM issues).
 */
import { sha256 } from "@noble/hashes/sha256";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = BigInt(ALPHABET.length); // 58

const ALPHABET_MAP = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP.set(ALPHABET[i], i);
}

function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function encodeBase58(data: Uint8Array): string {
  // count leading zeros
  let leadingZeros = 0;
  for (const byte of data) {
    if (byte !== 0) break;
    leadingZeros++;
  }

  // convert to bigint
  let num = BigInt(0);
  for (const byte of data) {
    num = num * BigInt(256) + BigInt(byte);
  }

  // encode
  let encoded = "";
  while (num > BigInt(0)) {
    const remainder = Number(num % BASE);
    num = num / BASE;
    encoded = ALPHABET[remainder] + encoded;
  }

  // prepend '1' for each leading zero byte
  return "1".repeat(leadingZeros) + encoded;
}

function decodeBase58(str: string): Uint8Array {
  // count leading '1's
  let leadingOnes = 0;
  for (const ch of str) {
    if (ch !== "1") break;
    leadingOnes++;
  }

  let num = BigInt(0);
  for (const ch of str) {
    const val = ALPHABET_MAP.get(ch);
    if (val === undefined) {
      throw new Error(`Invalid Base58 character: '${ch}'`);
    }
    num = num * BASE + BigInt(val);
  }

  // convert to bytes
  const hex = num === BigInt(0) ? "" : num.toString(16).padStart(2, "0");
  const paddedHex = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes = new Uint8Array(paddedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.slice(i * 2, i * 2 + 2), 16);
  }

  // prepend zero bytes
  const result = new Uint8Array(leadingOnes + bytes.length);
  result.set(bytes, leadingOnes);
  return result;
}

export const base58check = {
  /** Encode payload (version + data) with 4-byte checksum */
  encode(payload: Uint8Array): string {
    const checksum = doubleSha256(payload).slice(0, 4);
    const full = new Uint8Array(payload.length + 4);
    full.set(payload);
    full.set(checksum, payload.length);
    return encodeBase58(full);
  },

  /** Decode Base58Check string, verify checksum, return payload */
  decode(str: string): Uint8Array {
    const full = decodeBase58(str);
    if (full.length < 5) {
      throw new Error("Base58Check string too short");
    }
    const payload = full.slice(0, full.length - 4);
    const checksum = full.slice(full.length - 4);

    const expectedChecksum = doubleSha256(payload).slice(0, 4);
    for (let i = 0; i < 4; i++) {
      if (checksum[i] !== expectedChecksum[i]) {
        throw new Error("Base58Check checksum mismatch");
      }
    }
    return payload;
  },
};
