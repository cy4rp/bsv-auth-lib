import { describe, it, expect } from "vitest";
import {
  buildDerivationMessage,
  derivePrivateKeyFromSignature,
} from "../sign-to-derive.js";
import { isValidPrivateKey, bytesToHex } from "../keys.js";

describe("sign-to-derive", () => {
  describe("buildDerivationMessage", () => {
    it("includes the domain", () => {
      const msg = buildDerivationMessage("example.com");
      expect(msg).toContain("Domain: example.com");
    });

    it("includes safety notice", () => {
      const msg = buildDerivationMessage("test.local");
      expect(msg).toContain("NOT send any Ethereum transaction");
    });
  });

  describe("derivePrivateKeyFromSignature", () => {
    it("derives a valid secp256k1 key from 65-byte signature", () => {
      // Simulate a MetaMask personal_sign result (65 bytes: r(32) + s(32) + v(1))
      const fakeSig = new Uint8Array(65);
      fakeSig.fill(0xab);
      fakeSig[64] = 0x1b; // v = 27

      const key = derivePrivateKeyFromSignature(fakeSig);
      expect(key.length).toBe(32);
      expect(isValidPrivateKey(key)).toBe(true);
    });

    it("is deterministic for the same input", () => {
      const sig = new Uint8Array(65);
      sig.fill(0xcd);
      sig[64] = 0x1c;

      const key1 = derivePrivateKeyFromSignature(sig);
      const key2 = derivePrivateKeyFromSignature(sig);
      expect(bytesToHex(key1)).toBe(bytesToHex(key2));
    });

    it("different signatures produce different keys", () => {
      const sig1 = new Uint8Array(65);
      sig1.fill(0x01);
      const sig2 = new Uint8Array(65);
      sig2.fill(0x02);

      const key1 = derivePrivateKeyFromSignature(sig1);
      const key2 = derivePrivateKeyFromSignature(sig2);
      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });
  });
});
