# Encrypted SocialFi Backend (MVP)

A privacy-preserving social-networking backend: **end-to-end encrypted content**, **zero-knowledge login**, and a small **SocialFi** layer (token ledger + tipping). Node.js · Express 5 · PostgreSQL.

> The server never sees passwords, private keys, or plaintext content. It stores public keys, ciphertext, and wrapped keys.

## Quick start

```bash
# Option A: Docker (2 API replicas + nginx + Postgres)
docker compose up --build            # API on http://localhost:8080

# Option B: local
npm install
export DATABASE_URL=postgres://socialfi:socialfi@localhost:5432/socialfi
npm start                            # applies db/schema.sql on boot, listens on :3000
npm run demo                         # scripted walkthrough (second terminal)
npm test                             # 16 tests; needs DATABASE_URL pointing at a reachable Postgres
```

## How it works

### Zero-knowledge authentication (`src/crypto/zk.js`)
Non-interactive **Schnorr proof of knowledge** (Fiat–Shamir) over secp256k1. A user's identity is a keypair `P = x·G`; the secret `x` never leaves the device.

1. `POST /v1/auth/challenge` returns a single-use 32-byte nonce (stored in Postgres, 120 s TTL).
2. The client sends proof `(R, s)` where `R = k·G`, `c = H(domain, P, R, nonce, context)`, `s = k + c·x`.
3. The server checks `s·G == R + c·P` and consumes the nonce atomically (`DELETE … RETURNING`), so replays fail on **any** replica.

The proof is bound to the nonce (anti-replay) and a context string (`login`, or `register|handle|encPubkey`, so the handle and keys can't be swapped and registration proves possession of the key). Login returns a stateless HS256 JWT.

### End-to-end encryption (`sdk/e2ee.js`)
- Each post/DM gets a fresh 256-bit key and is encrypted with **AES-256-GCM**; the AAD binds the ciphertext to its item id.
- The content key is wrapped per recipient: **ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-GCM** ("envelopes", table `post_keys`).
- Access control is key possession: read endpoints only return items you hold an envelope for. The server also restricts audiences to the author's followers.
- Authors sign `(id, ciphertext)` with their identity key; the server verifies on write and clients verify on read (with trust-on-first-use key pinning), so a malicious server can't forge posts.
- New followers can't read old posts until the author grants access (`POST /v1/posts/:id/envelopes`; the SDK re-wraps the key locally).

### SocialFi
`accounts` + append-only `ledger_entries` + `tips`. Tips lock both account rows in a fixed order (no deadlocks, no overdraft), check idempotency *after* locking (safe retries, even concurrent ones), and require that you can read the post you tip. A test fires 12 concurrent 200-token tips against a 1000 balance and asserts exactly 5 succeed.

### Distributed-systems notes
API replicas are **stateless**: sessions are JWTs; ZK nonces, idempotency keys and the ledger live in Postgres. Schema migration uses an advisory lock so replicas can boot simultaneously. Graceful SIGTERM drain, `/healthz`, cursor pagination via a monotonic `seq`.

## API (under `/v1`, JSON; `Authorization: Bearer <jwt>` except `auth/*`)

| Method & path | Purpose |
|---|---|
| `POST /auth/challenge` | Get a single-use nonce |
| `POST /auth/register` | `{handle, identityPubkey, encPubkey, challengeId, proof}` |
| `POST /auth/login` | `{identityPubkey, challengeId, proof}` |
| `GET /users/me`, `GET /users/me/followers`, `GET /users/:handle` | Profile / audience / public keys |
| `POST` / `DELETE /users/:handle/follow` | Follow graph |
| `POST /posts` | `{id, ciphertext, signature, envelopes: {userId: wrappedKey}}` |
| `GET /posts/feed?before&limit`, `GET /posts/by/:handle`, `GET /posts/:id` | Read items you hold a key for |
| `POST /posts/:id/envelopes`, `DELETE /posts/:id` | Grant access / delete (author only) |
| `POST /messages`, `GET /messages?with=handle` | Encrypted DMs |
| `GET /wallet`, `POST /wallet/faucet`, `POST /wallet/tips` | Balance, test faucet, tip `{postId or toHandle, amount, idempotencyKey}` |

Client usage lives in `sdk/client.js` (`generateKeys`, `SocialFiClient`); see `scripts/demo.js`.

## Layout
```
src/             server (app, routes, ZK verifier, config, db)
sdk/             reference client: key generation, ZK prover, E2EE, signing
db/schema.sql    idempotent schema
test/            ZK/crypto unit tests + API integration tests
scripts/demo.js  end-to-end walkthrough
```

## Known MVP limitations
- **Metadata is visible**: handles, follow graph, timestamps, tip amounts, who messages whom. Only content is encrypted.
- **Key directory trust**: a malicious server could hand out a fake `encPubkey` for a user. The mitigation here is client-side TOFU pinning of identity keys; production should add fingerprint / safety-number verification.
- **No forward secrecy, key rotation or multi-device**: one static keypair per account; losing it loses the account and history (no recovery by design).
- **Schnorr over secp256k1 is a proof of key knowledge**, not a general-purpose SNARK. It's the right primitive for passwordless auth; richer ZK (anonymous membership, balance predicates) would be a next step (Semaphore / Groth16).
- Rate limiting is in-memory per replica (use a Redis store when scaling). JWTs aren't revocable before expiry. The "token" is an internal ledger, not on-chain; the faucet is dev-only (off by default in production). Not independently audited; have the crypto reviewed before handling real value.

## Next iterations
On-chain deposits/withdrawals, refresh tokens + device keys, encrypted media blobs (S3), group keys (MLS), websocket push, Redis-backed rate limits, SNARK-based anonymous gating.
