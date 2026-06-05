/**
 * @cy4rp/bsv-auth-lib
 *
 * BSV testnet authentication library.
 * Two auth methods, zero network switching:
 *
 * 1. WIF private key login
 * 2. MetaMask sign-to-derive (ETH signature → BSV key, no network change)
 *
 * @example
 * ```ts
 * import {
 *   authenticateWithWif,
 *   authenticateWithMetaMask,
 *   proveAuthentication,
 *   verifyAuthProof,
 *   generateChallenge,
 * } from "@cy4rp/bsv-auth-lib";
 *
 * // === WIF login ===
 * const auth = authenticateWithWif("cNxZ...");
 * console.log(auth.identity.address); // BSV testnet address
 *
 * // === MetaMask login (browser) ===
 * const auth2 = await authenticateWithMetaMask({ network: "testnet" });
 * console.log(auth2.identity.address);
 * console.log(auth2.ethAddress); // original ETH address
 *
 * // === Challenge-response (server-side verification) ===
 * const challenge = generateChallenge();
 * const proof = await proveAuthentication(auth.identity.wif, challenge);
 * const valid = verifyAuthProof(proof);
 * ```
 */

// ── High-level auth API ──
export {
  authenticateWithWif,
  authenticateWithMetaMask,
  proveAuthentication,
  verifyAuthProof,
  generateChallenge,
} from "./auth.js";

// ── MetaMask sign-to-derive ──
export {
  deriveFromMetaMask,
  buildDerivationMessage,
  derivePrivateKeyFromSignature,
} from "./sign-to-derive.js";

// ── BSV message signing ──
export {
  signMessage,
  verifyMessage,
  messageHash,
  createAuthProof,
} from "./signer.js";

// ── Key utilities ──
export {
  identityFromWif,
  identityFromPrivateKey,
  encodeWif,
  decodeWif,
  derivePublicKey,
  publicKeyToAddress,
  hash160,
  isValidPrivateKey,
  bytesToHex,
  hexToBytes,
} from "./keys.js";

// ── Base58Check ──
export { base58check } from "./base58check.js";

// ── Types ──
export type {
  BsvNetwork,
  BsvIdentity,
  AuthResult,
  AuthProof,
  Eip1193Provider,
  MetaMaskDeriveOptions,
  WifAuthOptions,
} from "./types.js";

export { WIF_VERSION, ADDRESS_VERSION } from "./types.js";
