import { describe, it, expect } from "vitest";
import {
  signMessage,
  verifyMessage,
  messageHash,
  generateChallenge,
  createAuthProof,
} from "../signer.js";
import { hexToBytes, bytesToHex, derivePublicKey } from "../keys.js";

const TEST_KEY = hexToBytes(
  "0000000000000000000000000000000000000000000000000000000000000001",
);

describe("signer", () => {
  describe("messageHash", () => {
    it("produces a 32-byte hash", () => {
      const hash = messageHash("hello");
      expect(hash.length).toBe(32);
    });

    it("is deterministic", () => {
      const h1 = messageHash("test message");
      const h2 = messageHash("test message");
      expect(bytesToHex(h1)).toBe(bytesToHex(h2));
    });

    it("different messages produce different hashes", () => {
      const h1 = messageHash("message A");
      const h2 = messageHash("message B");
      expect(bytesToHex(h1)).not.toBe(bytesToHex(h2));
    });
  });

  describe("signMessage + verifyMessage", () => {
    it("sign-then-verify round-trips", async () => {
      const msg = "Hello BSV from sign-to-derive!";
      const sig = await signMessage(TEST_KEY, msg);
      const pubHex = bytesToHex(derivePublicKey(TEST_KEY));
      expect(verifyMessage(sig, msg, pubHex)).toBe(true);
    });

    it("rejects a modified message", async () => {
      const sig = await signMessage(TEST_KEY, "original");
      const pubHex = bytesToHex(derivePublicKey(TEST_KEY));
      expect(verifyMessage(sig, "tampered", pubHex)).toBe(false);
    });

    it("rejects a wrong public key", async () => {
      const otherKey = hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000002",
      );
      const sig = await signMessage(TEST_KEY, "test");
      const otherPubHex = bytesToHex(derivePublicKey(otherKey));
      expect(verifyMessage(sig, "test", otherPubHex)).toBe(false);
    });
  });

  describe("generateChallenge", () => {
    it("includes the prefix", () => {
      const challenge = generateChallenge("bsv-auth");
      expect(challenge.startsWith("bsv-auth:")).toBe(true);
    });

    it("generates unique challenges", () => {
      const c1 = generateChallenge();
      const c2 = generateChallenge();
      expect(c1).not.toBe(c2);
    });
  });

  describe("createAuthProof", () => {
    it("produces a verifiable proof", async () => {
      const challenge = "test-challenge-123";
      const proof = await createAuthProof(TEST_KEY, challenge);
      expect(proof.signature).toBeTruthy();
      expect(proof.publicKey).toHaveLength(66);
      expect(verifyMessage(proof.signature, challenge, proof.publicKey)).toBe(
        true,
      );
    });
  });
});
