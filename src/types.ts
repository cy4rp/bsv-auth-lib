/** BSV network type */
export type BsvNetwork = "mainnet" | "testnet";

/** Version bytes for BSV WIF encoding */
export const WIF_VERSION: Record<BsvNetwork, number> = {
  mainnet: 0x80,
  testnet: 0xef,
};

/** Version bytes for BSV P2PKH addresses */
export const ADDRESS_VERSION: Record<BsvNetwork, number> = {
  mainnet: 0x00,
  testnet: 0x6f,
};

/** A BSV key pair with address */
export interface BsvIdentity {
  /** WIF-encoded private key */
  wif: string;
  /** Hex-encoded compressed public key (33 bytes) */
  publicKey: string;
  /** BSV P2PKH address (Base58Check) */
  address: string;
  /** Network this identity belongs to */
  network: BsvNetwork;
}

/** Authentication result */
export interface AuthResult {
  /** The BSV identity */
  identity: BsvIdentity;
  /** Authentication method used */
  method: "wif" | "metamask";
  /** For MetaMask: the Ethereum address that signed */
  ethAddress?: string;
  /** ISO 8601 timestamp of authentication */
  authenticatedAt: string;
}

/** Challenge-response proof for server-side verification */
export interface AuthProof {
  /** The challenge message that was signed */
  challenge: string;
  /** DER-encoded ECDSA signature (hex) */
  signature: string;
  /** Compressed public key (hex) */
  publicKey: string;
  /** BSV address */
  address: string;
  /** Network */
  network: BsvNetwork;
  /** Authentication method */
  method: "wif" | "metamask";
  /** For MetaMask: the Ethereum address */
  ethAddress?: string;
  /** ISO 8601 timestamp */
  timestamp: string;
}

/** EIP-1193 provider (MetaMask window.ethereum) */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, handler: (...args: unknown[]) => void): void;
  removeListener?(event: string, handler: (...args: unknown[]) => void): void;
}

/** Options for MetaMask sign-to-derive */
export interface MetaMaskDeriveOptions {
  /** Custom domain identifier for key derivation (default: window.location.host) */
  domain?: string;
  /** BSV network (default: "testnet") */
  network?: BsvNetwork;
  /** EIP-1193 provider override (default: window.ethereum) */
  provider?: Eip1193Provider;
}

/** Options for WIF authentication */
export interface WifAuthOptions {
  /** BSV network (default: "testnet") */
  network?: BsvNetwork;
}
