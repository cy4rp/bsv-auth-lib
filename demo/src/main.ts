import {
  authenticateWithWif,
  authenticateWithMetaMask,
  proveAuthentication,
  verifyAuthProof,
  generateChallenge,
  identityFromPrivateKey,
  encodeWif,
  type AuthResult,
  type BsvNetwork,
} from "@cy4rp/bsv-auth-lib";

// ── State ──

let currentNetwork: BsvNetwork = "testnet";
let currentAuth: AuthResult | null = null;

// ── DOM Refs ──

const $ = <T extends HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

const btnTestnet = $<HTMLButtonElement>("btn-testnet");
const btnMainnet = $<HTMLButtonElement>("btn-mainnet");
const wifInput = $<HTMLInputElement>("wif-input");
const btnWifLogin = $<HTMLButtonElement>("btn-wif-login");
const btnWifGenerate = $<HTMLButtonElement>("btn-wif-generate");
const btnToggleVis = $<HTMLButtonElement>("wif-toggle-vis");
const btnMmLogin = $<HTMLButtonElement>("btn-mm-login");
const mmStatus = $<HTMLDivElement>("mm-status");
const resultPanel = $<HTMLDivElement>("result-panel");
const badgeMethod = $<HTMLSpanElement>("badge-method");
const badgeNetwork = $<HTMLSpanElement>("badge-network");
const resAddress = $<HTMLElement>("res-address");
const resPubkey = $<HTMLElement>("res-pubkey");
const resEthRow = $<HTMLDivElement>("res-eth-row");
const resEth = $<HTMLElement>("res-eth");
const resTime = $<HTMLElement>("res-time");
const btnProve = $<HTMLButtonElement>("btn-prove");
const proofResult = $<HTMLDivElement>("proof-result");
const proofChallenge = $<HTMLElement>("proof-challenge");
const proofSig = $<HTMLElement>("proof-sig");
const proofVerify = $<HTMLDivElement>("proof-verify");
const btnLogout = $<HTMLButtonElement>("btn-logout");

// ── Network Toggle ──

function setNetwork(network: BsvNetwork) {
  currentNetwork = network;
  btnTestnet.classList.toggle("active", network === "testnet");
  btnMainnet.classList.toggle("active", network === "mainnet");
}

btnTestnet.addEventListener("click", () => setNetwork("testnet"));
btnMainnet.addEventListener("click", () => setNetwork("mainnet"));

// ── WIF Visibility Toggle ──

btnToggleVis.addEventListener("click", () => {
  const isPassword = wifInput.type === "password";
  wifInput.type = isPassword ? "text" : "password";
});

// ── Generate Test Key ──

btnWifGenerate.addEventListener("click", () => {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const identity = identityFromPrivateKey(randomBytes, currentNetwork);
  wifInput.value = identity.wif;
  wifInput.type = "text";
});

// ── WIF Login ──

btnWifLogin.addEventListener("click", () => {
  const wif = wifInput.value.trim();
  if (!wif) {
    showMmStatus("WIF を入力してください", "error");
    return;
  }

  try {
    const auth = authenticateWithWif(wif);
    currentAuth = auth;
    showResult(auth);
  } catch (err) {
    showMmStatus(`WIF エラー: ${(err as Error).message}`, "error");
  }
});

// ── MetaMask Login ──

btnMmLogin.addEventListener("click", async () => {
  showMmStatus("MetaMask に接続中...", "");

  try {
    const auth = await authenticateWithMetaMask({
      network: currentNetwork,
    });
    currentAuth = auth;
    showMmStatus("接続成功", "success");
    showResult(auth);
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes("MetaMask not found")) {
      showMmStatus("MetaMask が見つかりません。拡張機能をインストールしてください。", "error");
    } else if (msg.includes("User denied") || msg.includes("rejected")) {
      showMmStatus("署名がキャンセルされました", "error");
    } else {
      showMmStatus(`エラー: ${msg}`, "error");
    }
  }
});

// ── Show Result ──

function showResult(auth: AuthResult) {
  resultPanel.classList.remove("hidden");

  // Method badge
  badgeMethod.textContent = auth.method === "wif" ? "WIF" : "MetaMask";
  badgeMethod.className =
    `badge ${auth.method === "wif" ? "badge-wif" : "badge-metamask"}`;

  // Network badge
  badgeNetwork.textContent = auth.identity.network;

  // Identity
  resAddress.textContent = auth.identity.address;
  resPubkey.textContent = auth.identity.publicKey;
  resTime.textContent = new Date(auth.authenticatedAt).toLocaleString("ja-JP");

  // ETH address (only for MetaMask)
  if (auth.ethAddress) {
    resEthRow.classList.remove("hidden");
    resEth.textContent = auth.ethAddress;
  } else {
    resEthRow.classList.add("hidden");
  }

  // Reset proof
  proofResult.classList.add("hidden");

  // Scroll to result
  resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Challenge-Response ──

btnProve.addEventListener("click", async () => {
  if (!currentAuth) return;

  btnProve.disabled = true;
  btnProve.textContent = "署名中...";

  try {
    const challenge = generateChallenge();
    const proof = await proveAuthentication(
      currentAuth.identity.wif,
      challenge,
      currentAuth.method,
      currentAuth.ethAddress,
    );

    const valid = verifyAuthProof(proof);

    proofChallenge.textContent = proof.challenge;
    proofSig.textContent = proof.signature;
    proofVerify.textContent = valid ? "VERIFIED — 署名は有効です" : "FAILED — 署名が無効です";
    proofVerify.className = `verify-result ${valid ? "pass" : "fail"}`;

    proofResult.classList.remove("hidden");
  } catch (err) {
    proofVerify.textContent = `エラー: ${(err as Error).message}`;
    proofVerify.className = "verify-result fail";
    proofResult.classList.remove("hidden");
  } finally {
    btnProve.disabled = false;
    btnProve.textContent = "署名して検証";
  }
});

// ── Logout ──

btnLogout.addEventListener("click", () => {
  currentAuth = null;
  resultPanel.classList.add("hidden");
  wifInput.value = "";
  showMmStatus("", "");
  mmStatus.classList.add("hidden");
});

// ── Helpers ──

function showMmStatus(msg: string, type: string) {
  mmStatus.textContent = msg;
  mmStatus.className = `status-line ${type}`;
  mmStatus.classList.toggle("hidden", !msg);
}
