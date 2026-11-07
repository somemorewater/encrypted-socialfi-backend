-- Encrypted SocialFi schema. Idempotent: safe to run on every boot.
-- The server only ever stores CIPHERTEXT for user content. Plaintext never reaches this DB.

CREATE TABLE IF NOT EXISTS users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  handle            text NOT NULL,
  identity_pubkey   text NOT NULL,          -- secp256k1 compressed point (hex). Used for ZK auth + signatures.
  enc_pubkey        text NOT NULL,          -- X25519 public key (hex). Used to receive wrapped content keys.
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_handle_format CHECK (handle ~ '^[a-z0-9_]{3,24}$')
);
CREATE UNIQUE INDEX IF NOT EXISTS users_handle_key   ON users (handle);
CREATE UNIQUE INDEX IF NOT EXISTS users_identity_key ON users (identity_pubkey);

-- Single-use, short-lived server nonces for ZK proofs. Stored in PG (not memory) so
-- any API replica can issue a challenge and any other replica can verify it.
CREATE TABLE IF NOT EXISTS auth_challenges (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce       text NOT NULL,                -- 32 random bytes, hex
  expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_challenges_expiry ON auth_challenges (expires_at);

CREATE TABLE IF NOT EXISTS follows (
  follower_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  followee_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (follower_id, followee_id),
  CHECK (follower_id <> followee_id)
);
CREATE INDEX IF NOT EXISTS follows_followee ON follows (followee_id);

-- Encrypted posts. `ciphertext` is AES-256-GCM output produced on the client.
CREATE TABLE IF NOT EXISTS posts (
  id          uuid PRIMARY KEY,             -- client-generated; bound into the AEAD associated data
  seq         bigserial NOT NULL,           -- monotonic cursor for pagination
  author_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext  text NOT NULL,                -- base64(iv || tag || ct)
  signature   text NOT NULL,                -- author's secp256k1 signature over (id, ciphertext)
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS posts_seq_key ON posts (seq);
CREATE INDEX IF NOT EXISTS posts_author ON posts (author_id, seq DESC);

-- One wrapped content key per authorised reader. The server cannot unwrap these.
CREATE TABLE IF NOT EXISTS post_keys (
  post_id        uuid NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  recipient_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_key    text NOT NULL,             -- base64(ephemeralPub || iv || tag || wrapped)
  PRIMARY KEY (post_id, recipient_id)
);
CREATE INDEX IF NOT EXISTS post_keys_recipient ON post_keys (recipient_id, post_id);

-- Encrypted direct messages (1:1). Two wrapped keys: one for each party.
CREATE TABLE IF NOT EXISTS messages (
  id                  uuid PRIMARY KEY,
  seq                 bigserial NOT NULL,
  sender_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext          text NOT NULL,
  signature           text NOT NULL,
  key_for_sender      text NOT NULL,
  key_for_recipient   text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS messages_seq_key ON messages (seq);
CREATE INDEX IF NOT EXISTS messages_recipient ON messages (recipient_id, seq DESC);
CREATE INDEX IF NOT EXISTS messages_sender    ON messages (sender_id, seq DESC);

-- ---- SocialFi: internal token ledger + tipping ----
CREATE TABLE IF NOT EXISTS accounts (
  user_id  uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  balance  bigint NOT NULL DEFAULT 0 CHECK (balance >= 0)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id          bigserial PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  delta       bigint NOT NULL CHECK (delta <> 0),
  kind        text NOT NULL CHECK (kind IN ('faucet','tip_sent','tip_received')),
  ref_id      uuid,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ledger_user ON ledger_entries (user_id, id DESC);

CREATE TABLE IF NOT EXISTS tips (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_user        uuid NOT NULL REFERENCES users(id),
  to_user          uuid NOT NULL REFERENCES users(id),
  post_id          uuid REFERENCES posts(id) ON DELETE SET NULL,
  amount           bigint NOT NULL CHECK (amount > 0),
  idempotency_key  text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (from_user, idempotency_key)       -- safe client retries across replicas
);
