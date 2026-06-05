import { describe, it, expect } from "vitest";
import {
  authenticateWithWif,
  proveAuthentication,
  verifyAuthProof,
  generateChallenge,
} from "../auth.js";
import { encodeWif, hexToBytes } from "../keys.js";

const TEST_KEY = hexToBytes(
  "0000000000000000000000000000000000000000000000000000000000000001",
);
const TEST_WIF_TESTNET = encodeWif(TEST_KEY, "testnet");
const TEST_WIF_MAINNET = encodeWif(TEST_KEY, "mainnet");

describe("auth", () => {
  describe("authenticateWithWif", () => {
    it("authenticates with a testnet WIF", () => {
      const result = authenticateWithWif(TEST_WIF_TESTNET);
      expect(result.method).toBe("wif");
      expect(result.identity.network).toBe("testnet");
      expect(result.identity.address).toBeTruthy();
      expect(result.authenticatedAt).toBeTruthy();
    });

    it("authenticates with a mainnet WIF", () => {
      const result = authenticateWithWif(TEST_WIF_MAINNET);
      expect(result.method).toBe("wif");
      expect(result.identity.network).toBe("mainnet");
    });

    it("rejects network mismatch", () => {
      expect(() =>
        authenticateWithWif(TEST_WIF_TESTNET, { network: "mainnet" }),
      ).toThrow("WIF encodes testnet but options specify mainnet");
    });
  });

  describe("proveAuthentication + verifyAuthProof", () => {
    it("full challenge-response cycle", async () => {
      const challenge = generateChallenge();
      const proof = await proveAuthentication(TEST_WIF_TESTNET, challenge);

      expect(proof.challenge).toBe(challenge);
      expect(proof.signature).toBeTruthy();
      expect(proof.publicKey).toHaveLength(66);
      expect(proof.address).toBeTruthy();
      expect(proof.network).toBe("testnet");
      expect(proof.method).toBe("wif");

      const valid = verifyAuthProof(proof);
      expect(valid).toBe(true);
    });

    it("rejects tampered challenge", async () => {
      const challenge = generateChallenge();
      const proof = await proveAuthentication(TEST_WIF_TESTNET, challenge);

      proof.challenge = "tampered-challenge";
      expect(verifyAuthProof(proof)).toBe(false);
    });

    it("rejects tampered address", async () => {
      const challenge = generateChallenge();
      const proof = await proveAuthentication(TEST_WIF_TESTNET, challenge);

      proof.address = "mWrongAddress123456789";
      expect(verifyAuthProof(proof)).toBe(false);
    });
  });
});
