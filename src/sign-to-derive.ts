/**
 * MetaMask sign-to-derive: deterministic BSV key derivation from an
 * Ethereum personal_sign signature.
 *
 * Flow:
 * 1. Build a domain-scoped derivation message
 * 2. Request `personal_sign` from MetaMask (user approves)
 * 3. SHA-256 the 65-byte signature → 32-byte BSV private key
 * 4. If the hash is not a valid secp256k1 scalar, HMAC-iterate
 *
 * Security properties:
 * - ETH private key never leaves MetaMask
 * - Signature → BSV key is one-way (SHA-256 preimage resistance)
 * - Deterministic: same ETH account + same domain → same BSV key
 * - Domain-scoped: different domains → different BSV keys
 */
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { isValidPrivateKey, identityFromPrivateKey, hexToBytes } from "./keys.js";
import type {
  BsvIdentity,
  BsvNetwork,
  Eip1193Provider,
  MetaMaskDeriveOptions,
} from "./types.js";

/** The derivation message MetaMask will sign. Domain-scoped to prevent cross-site key reuse. */
export function buildDerivationMessage(domain: string): string {
  return [
    "BSV Authentication Key Derivation",
    "",
    `Domain: ${domain}`,
    "Purpose: Derive a BSV signing key from this Ethereum account.",
    "",
    "This signature will NOT send any Ethereum transaction.",
    "Your ETH private key remains safe inside MetaMask.",
    "",
    "Technical: SHA-256(signature) → BSV secp256k1 private key",
  ].join("\n");
}

/**
 * Derive a 32-byte BSV private key from a 65-byte ETH signature.
 *
 * Uses SHA-256, with HMAC-SHA256 iteration if the initial hash
 * falls outside the valid secp256k1 scalar range [1, n-1].
 * This is astronomically unlikely but handled for correctness.
 */
export function derivePrivateKeyFromSignature(
  signatureBytes: Uint8Array,
): Uint8Array {
  let candidate = sha256(signatureBytes);

  // Iterate with HMAC if candidate is not a valid scalar (probability ≈ 2^-128)
  for (let i = 0; i < 256; i++) {
    if (isValidPrivateKey(candidate)) {
      return candidate;
    }
    candidate = hmac(sha256, candidate, new Uint8Array([i]));
  }

  throw new Error(
    "Failed to derive valid private key after 256 iterations (should never happen)",
  );
}

/**
 * Request MetaMask to sign the derivation message and return a BSV identity.
 *
 * @throws if MetaMask is not available or user rejects the signature
 */
export async function deriveFromMetaMask(
  options: MetaMaskDeriveOptions = {},
): Promise<{ identity: BsvIdentity; ethAddress: string }> {
  const {
    domain = typeof window !== "undefined" ? window.location.host : "localhost",
    network = "testnet" as BsvNetwork,
    provider = getProvider(),
  } = options;

  // 1. Get the user's Ethereum address
  const accounts = (await provider.request({
    method: "eth_requestAccounts",
  })) as string[];

  if (!accounts || accounts.length === 0) {
    throw new Error("No Ethereum accounts available");
  }
  const ethAddress = accounts[0].toLowerCase();

  // 2. Build the derivation message
  const message = buildDerivationMessage(domain);

  // 3. Request personal_sign (MetaMask popup)
  const signatureHex = (await provider.request({
    method: "personal_sign",
    params: [
      stringToHex(message),
      ethAddress,
    ],
  })) as string;

  // 4. Convert hex signature to bytes (strip 0x prefix)
  const sigBytes = hexToBytes(signatureHex.replace(/^0x/, ""));

  // 5. Derive BSV private key
  const bsvPrivateKey = derivePrivateKeyFromSignature(sigBytes);

  // 6. Build identity
  const identity = identityFromPrivateKey(bsvPrivateKey, network);

  return { identity, ethAddress };
}

/** Get the EIP-1193 provider from the browser environment */
function getProvider(): Eip1193Provider {
  if (typeof window === "undefined") {
    throw new Error(
      "MetaMask sign-to-derive requires a browser environment",
    );
  }
  const eth = (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
  if (!eth) {
    throw new Error(
      "MetaMask not found. Please install MetaMask browser extension.",
    );
  }
  return eth;
}

/** Convert a UTF-8 string to 0x-prefixed hex */
function stringToHex(str: string): string {
  const bytes = new TextEncoder().encode(str);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return "0x" + hex;
}
