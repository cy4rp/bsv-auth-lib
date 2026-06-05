import { describe, it, expect } from "vitest";
import {
  encodeWif,
  decodeWif,
  identityFromPrivateKey,
  identityFromWif,
  derivePublicKey,
  publicKeyToAddress,
  isValidPrivateKey,
  bytesToHex,
  hexToBytes,
} from "../keys.js";

// Known test vector: a deterministic 32-byte key
const TEST_KEY = hexToBytes(
  "0000000000000000000000000000000000000000000000000000000000000001",
);

describe("keys", () => {
  describe("isValidPrivateKey", () => {
    it("accepts a valid private key", () => {
      expect(isValidPrivateKey(TEST_KEY)).toBe(true);
    });

    it("rejects all-zero key", () => {
      expect(isValidPrivateKey(new Uint8Array(32))).toBe(false);
    });
  });

  describe("WIF encoding/decoding", () => {
    it("round-trips a testnet WIF", () => {
      const wif = encodeWif(TEST_KEY, "testnet");
      expect(wif.startsWith("c")).toBe(true); // testnet compressed WIF starts with 'c'
      const decoded = decodeWif(wif);
      expect(bytesToHex(decoded.privateKey)).toBe(bytesToHex(TEST_KEY));
      expect(decoded.network).toBe("testnet");
    });

    it("round-trips a mainnet WIF", () => {
      const wif = encodeWif(TEST_KEY, "mainnet");
      expect(wif.startsWith("K") || wif.startsWith("L")).toBe(true); // mainnet compressed WIF
      const decoded = decodeWif(wif);
      expect(bytesToHex(decoded.privateKey)).toBe(bytesToHex(TEST_KEY));
      expect(decoded.network).toBe("mainnet");
    });

    it("rejects invalid checksum", () => {
      const wif = encodeWif(TEST_KEY, "testnet");
      // Corrupt last character
      const corrupted = wif.slice(0, -1) + (wif.endsWith("A") ? "B" : "A");
      expect(() => decodeWif(corrupted)).toThrow();
    });
  });

  describe("derivePublicKey", () => {
    it("derives a 33-byte compressed public key", () => {
      const pub = derivePublicKey(TEST_KEY);
      expect(pub.length).toBe(33);
      // Key 1 has a known public key
      expect(bytesToHex(pub)).toBe(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      );
    });
  });

  describe("publicKeyToAddress", () => {
    it("produces a valid testnet address", () => {
      const pub = derivePublicKey(TEST_KEY);
      const addr = publicKeyToAddress(pub, "testnet");
      expect(addr.startsWith("m") || addr.startsWith("n")).toBe(true);
    });

    it("produces a valid mainnet address", () => {
      const pub = derivePublicKey(TEST_KEY);
      const addr = publicKeyToAddress(pub, "mainnet");
      expect(addr.startsWith("1")).toBe(true);
    });
  });

  describe("identityFromPrivateKey", () => {
    it("builds a full identity", () => {
      const id = identityFromPrivateKey(TEST_KEY, "testnet");
      expect(id.wif).toBeTruthy();
      expect(id.publicKey).toHaveLength(66); // 33 bytes hex
      expect(id.address).toBeTruthy();
      expect(id.network).toBe("testnet");
    });
  });

  describe("identityFromWif", () => {
    it("reconstructs identity from WIF", () => {
      const id1 = identityFromPrivateKey(TEST_KEY, "testnet");
      const id2 = identityFromWif(id1.wif);
      expect(id2.publicKey).toBe(id1.publicKey);
      expect(id2.address).toBe(id1.address);
      expect(id2.network).toBe(id1.network);
    });
  });

  describe("hex helpers", () => {
    it("bytesToHex and hexToBytes round-trip", () => {
      const hex = "deadbeef0123456789abcdef";
      expect(bytesToHex(hexToBytes(hex))).toBe(hex);
    });

    it("rejects odd-length hex", () => {
      expect(() => hexToBytes("abc")).toThrow("Odd-length hex string");
    });
  });
});
