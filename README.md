# @cy4rp/bsv-auth-lib

BSV テストネット認証ライブラリ — **WIF 秘密鍵ログイン** & **MetaMask sign-to-derive**。

MetaMask のネットワーク追加・切替は一切不要。イーサリアム・メインネットの `personal_sign` 署名を Web 側で BSV 秘密鍵に変換します。

## 特徴

- **WIF ログイン**: BSV WIF 秘密鍵を直接インポートして認証
- **MetaMask ログイン**: `personal_sign` で署名 → SHA-256 → BSV secp256k1 鍵を決定論導出
- **ネットワーク切替不要**: MetaMask は Ethereum メインネットのまま
- **ETH 秘密鍵安全**: ECDLP 困難性 + SHA-256 一方向性で二重に保護
- **チャレンジ・レスポンス**: サーバーサイド検証用の署名認証プルーフ
- **ゼロ外部依存**: `@noble/secp256k1` + `@noble/hashes` のみ（監査済み純 JS）
- **ESM + CJS**: デュアルフォーマット出力、TypeScript 型定義付き

## インストール

```bash
npm install @cy4rp/bsv-auth-lib
```

## 使い方

### 1. WIF 秘密鍵ログイン

```ts
import { authenticateWithWif } from "@cy4rp/bsv-auth-lib";

const auth = authenticateWithWif("cNxZ...");  // テストネット WIF
console.log(auth.identity.address);  // BSV テストネットアドレス
console.log(auth.identity.publicKey); // 圧縮公開鍵 (hex)
```

### 2. MetaMask ログイン（ブラウザ）

```ts
import { authenticateWithMetaMask } from "@cy4rp/bsv-auth-lib";

// MetaMask ポップアップが表示される（署名のみ、ETH送金なし）
const auth = await authenticateWithMetaMask({
  network: "testnet",
  // domain: "mysite.com"  // 省略時は window.location.host
});

console.log(auth.identity.address);  // BSV テストネットアドレス
console.log(auth.ethAddress);         // 元の ETH アドレス
```

### 3. チャレンジ・レスポンス認証（サーバーサイド検証）

```ts
import {
  generateChallenge,
  proveAuthentication,
  verifyAuthProof,
} from "@cy4rp/bsv-auth-lib";

// サーバー: チャレンジ生成
const challenge = generateChallenge();

// クライアント: チャレンジに署名
const proof = await proveAuthentication(auth.identity.wif, challenge);

// サーバー: 検証
const valid = verifyAuthProof(proof);
// → true: 署名が有効 & アドレスが公開鍵に一致
```

### 4. 低レベル API

```ts
import {
  identityFromPrivateKey,
  signMessage,
  verifyMessage,
  derivePrivateKeyFromSignature,
  hexToBytes,
} from "@cy4rp/bsv-auth-lib";

// 32バイト秘密鍵から ID を構築
const key = hexToBytes("abcd...");
const id = identityFromPrivateKey(key, "testnet");

// BSV メッセージ署名
const sig = await signMessage(key, "Hello BSV!");
const ok = verifyMessage(sig, "Hello BSV!", id.publicKey);
```

## sign-to-derive の仕組み

```
┌─────────────────────────────────────────────────────────┐
│  Browser                                                │
│                                                         │
│  1. msg = "BSV Auth Key Derivation\nDomain: mysite.com" │
│                                                         │
│  2. sig = MetaMask.personal_sign(msg, ethAddress)       │
│     ↓  MetaMask 内部で ECDSA 署名                       │
│     ↓  秘密鍵は MetaMask 内に留まる                     │
│     ↓  返るのは sig (65 bytes: r‖s‖v) のみ              │
│                                                         │
│  3. bsvKey = SHA-256(sig)                               │
│     → 32-byte secp256k1 秘密鍵（BSV用）                │
│     → ETH 秘密鍵とは完全に別の値                        │
│                                                         │
│  4. bsvAddress = P2PKH(HASH160(pubKey(bsvKey)))         │
│     → BSV テストネットアドレス                          │
└─────────────────────────────────────────────────────────┘
```

### セキュリティ

| 懸念 | 回答 |
|---|---|
| 署名から ETH 秘密鍵を逆算？ | ECDLP 困難性により計算上不可能 |
| BSV 鍵から ETH 秘密鍵を逆算？ | SHA-256 の一方向性により不可能 |
| MetaMask が秘密鍵を渡す？ | API 設計上、署名結果のみ返す |
| 別ドメインで同じ鍵が導出？ | ドメインスコープにより別鍵になる |

## API リファレンス

### 認証

| 関数 | 説明 |
|---|---|
| `authenticateWithWif(wif, options?)` | WIF 秘密鍵で認証 |
| `authenticateWithMetaMask(options?)` | MetaMask sign-to-derive で認証 |
| `proveAuthentication(wif, challenge)` | チャレンジ・レスポンス証明を生成 |
| `verifyAuthProof(proof)` | 認証プルーフを検証 |
| `generateChallenge(prefix?)` | ランダムチャレンジ文字列を生成 |

### 鍵操作

| 関数 | 説明 |
|---|---|
| `identityFromWif(wif)` | WIF から BsvIdentity を構築 |
| `identityFromPrivateKey(key, network)` | 生秘密鍵から BsvIdentity を構築 |
| `encodeWif(key, network)` | 秘密鍵を WIF にエンコード |
| `decodeWif(wif)` | WIF をデコード |

### 署名

| 関数 | 説明 |
|---|---|
| `signMessage(key, message)` | BSV メッセージ署名 |
| `verifyMessage(sig, message, pubKey)` | 署名を検証 |

### sign-to-derive

| 関数 | 説明 |
|---|---|
| `deriveFromMetaMask(options?)` | MetaMask 署名から BSV ID を導出 |
| `derivePrivateKeyFromSignature(sig)` | 署名バイトから秘密鍵を導出 |
| `buildDerivationMessage(domain)` | 導出用メッセージを構築 |

## 開発

```bash
npm install
npm test          # テスト実行
npm run typecheck # 型チェック
npm run build     # ビルド (ESM + CJS + .d.ts)
```

## ライセンス

MIT
