/**
 * High-level authentication API.
 *
 * Two methods:
 * 1. authenticateWithWif()  — import a BSV WIF private key
 * 2. authenticateWithMetaMask() — sign-to-derive from MetaMask
 *
 * Both return an AuthResult, and optionally produce an AuthProof
 * (challenge-response) for server-side verification.
 */
import { identityFromWif, decodeWif } from "./keys.js";
import { deriveFromMetaMask } from "./sign-to-derive.js";
import {
  generateChallenge,
  createAuthProof,
  verifyMessage,
} from "./signer.js";
import { publicKeyToAddress, hexToBytes } from "./keys.js";
import type {
  AuthResult,
  AuthProof,
  WifAuthOptions,
  MetaMaskDeriveOptions,
} from "./types.js";

/**
 * Authenticate using a WIF private key.
 *
 * @param wif - WIF-encoded BSV private key
 * @param options - Network override (auto-detected from WIF prefix by default)
 */
export function authenticateWithWif(
  wif: string,
  options: WifAuthOptions = {},
): AuthResult {
  const identity = identityFromWif(wif);

  // Allow network override but default to what's encoded in WIF
  if (options.network && options.network !== identity.network) {
    throw new Error(
      `WIF encodes ${identity.network} but options specify ${options.network}. ` +
        "Use a WIF matching the desired network.",
    );
  }

  return {
    identity,
    method: "wif",
    authenticatedAt: new Date().toISOString(),
  };
}

/**
 * Authenticate using MetaMask sign-to-derive.
 *
 * The user will see a MetaMask popup to sign a derivation message.
 * No ETH transaction is sent; the signature deterministically derives
 * a BSV private key.
 *
 * @param options - Domain, network, and provider overrides
 */
export async function authenticateWithMetaMask(
  options: MetaMaskDeriveOptions = {},
): Promise<AuthResult> {
  const { identity, ethAddress } = await deriveFromMetaMask(options);

  return {
    identity,
    method: "metamask",
    ethAddress,
    authenticatedAt: new Date().toISOString(),
  };
}

/**
 * Generate a challenge-response authentication proof.
 *
 * Use this for server-side verification:
 * 1. Server sends a challenge (random string)
 * 2. Client signs the challenge with their BSV key
 * 3. Server verifies the signature
 *
 * @param wif - WIF private key to sign with
 * @param challenge - Challenge string (use generateChallenge() on server)
 */
export async function proveAuthentication(
  wif: string,
  challenge: string,
  method: "wif" | "metamask" = "wif",
  ethAddress?: string,
): Promise<AuthProof> {
  const { privateKey, network } = decodeWif(wif);
  const { signature, publicKey } = await createAuthProof(privateKey, challenge);
  const identity = identityFromWif(wif);

  return {
    challenge,
    signature,
    publicKey,
    address: identity.address,
    network,
    method,
    ethAddress,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Verify an authentication proof (server-side).
 *
 * @returns true if the signature is valid and the address matches
 */
export function verifyAuthProof(proof: AuthProof): boolean {
  // 1. Verify the signature
  const signatureValid = verifyMessage(
    proof.signature,
    proof.challenge,
    proof.publicKey,
  );
  if (!signatureValid) return false;

  // 2. Verify the address matches the public key
  const pubBytes = hexToBytes(proof.publicKey);
  const expectedAddress = publicKeyToAddress(pubBytes, proof.network);
  return expectedAddress === proof.address;
}

export { generateChallenge };
