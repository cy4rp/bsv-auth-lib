/**
 * Low-level secp256k1 key operations for BSV.
 *
 * Uses @noble/secp256k1 (audited, pure-JS) for all curve math
 * and @noble/hashes for SHA-256 / RIPEMD-160.
 */
import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58check } from "./base58check.js";
import {
  type BsvNetwork,
  type BsvIdentity,
  WIF_VERSION,
  ADDRESS_VERSION,
} from "./types.js";

/** Validate that a 32-byte buffer is a valid secp256k1 private key */
export function isValidPrivateKey(key: Uint8Array): boolean {
  try {
    secp.getPublicKey(key, true);
    return true;
  } catch {
    return false;
  }
}

/** Derive compressed public key (33 bytes) from a 32-byte private key */
export function derivePublicKey(privateKey: Uint8Array): Uint8Array {
  return secp.getPublicKey(privateKey, true);
}

/** Compute HASH160 = RIPEMD160(SHA256(data)) */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/** Encode a private key as WIF (Wallet Import Format) */
export function encodeWif(
  privateKey: Uint8Array,
  network: BsvNetwork = "testnet",
): string {
  const version = WIF_VERSION[network];
  // compressed WIF: version(1) + key(32) + compression_flag(1)
  const payload = new Uint8Array(34);
  payload[0] = version;
  payload.set(privateKey, 1);
  payload[33] = 0x01; // compressed
  return base58check.encode(payload);
}

/** Decode a WIF string back to a 32-byte private key and network */
export function decodeWif(wif: string): {
  privateKey: Uint8Array;
  network: BsvNetwork;
} {
  const payload = base58check.decode(wif);

  let network: BsvNetwork;
  if (payload[0] === WIF_VERSION.mainnet) {
    network = "mainnet";
  } else if (payload[0] === WIF_VERSION.testnet) {
    network = "testnet";
  } else {
    throw new Error(`Unknown WIF version byte: 0x${payload[0].toString(16)}`);
  }

  // compressed WIF = 34 bytes, uncompressed = 33 bytes
  if (payload.length === 34 && payload[33] === 0x01) {
    return { privateKey: payload.slice(1, 33), network };
  }
  if (payload.length === 33) {
    return { privateKey: payload.slice(1, 33), network };
  }
  throw new Error(`Invalid WIF payload length: ${payload.length}`);
}

/** Compute a BSV P2PKH address from a compressed public key */
export function publicKeyToAddress(
  publicKey: Uint8Array,
  network: BsvNetwork = "testnet",
): string {
  const h160 = hash160(publicKey);
  const versioned = new Uint8Array(21);
  versioned[0] = ADDRESS_VERSION[network];
  versioned.set(h160, 1);
  return base58check.encode(versioned);
}

/** Build a full BsvIdentity from a 32-byte private key */
export function identityFromPrivateKey(
  privateKey: Uint8Array,
  network: BsvNetwork = "testnet",
): BsvIdentity {
  if (!isValidPrivateKey(privateKey)) {
    throw new Error("Invalid secp256k1 private key");
  }
  const pubKey = derivePublicKey(privateKey);
  return {
    wif: encodeWif(privateKey, network),
    publicKey: bytesToHex(pubKey),
    address: publicKeyToAddress(pubKey, network),
    network,
  };
}

/** Build a BsvIdentity from a WIF string */
export function identityFromWif(wif: string): BsvIdentity {
  const { privateKey, network } = decodeWif(wif);
  return identityFromPrivateKey(privateKey, network);
}

// ── hex helpers ──

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Odd-length hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
