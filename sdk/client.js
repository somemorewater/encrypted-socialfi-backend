// Reference client SDK. ALL cryptography (key generation, ZK proving, encryption, signing)
// happens here, on the user's device. The server only ever receives public keys, proofs and ciphertext.
import crypto from 'node:crypto';
import { generateIdentity, prove, signParts, verifyParts } from '../src/crypto/zk.js';
import {
  generateEncryptionKeypair,
  encryptForRecipients,
  decryptItem,
  decryptContentKey,
  wrapContentKeyFor,
} from './e2ee.js';

export function generateKeys() {
  const id = generateIdentity();
  const enc = generateEncryptionKeypair();
  return { identitySecret: id.secret, identityPubkey: id.pub, encSecret: enc.secret, encPubkey: enc.pub };
}

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message ?? `HTTP ${status}`);
    this.status = status;
    this.code = body?.error?.code;
    this.body = body;
  }
}

export class SocialFiClient {
  /** @param keys  output of generateKeys(); keep it on-device — it is the user's account. */
  constructor({ baseUrl, keys }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.keys = keys;
    this.token = null;
    this.user = null;
    this.pinned = new Map(); // handle -> identityPubkey (trust-on-first-use pinning)
  }

  async #http(method, path, body, { auth = true } = {}) {
    const res = await fetch(this.baseUrl + path, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(auth && this.token ? { authorization: `Bearer ${this.token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : null;
    if (!res.ok) throw new ApiError(res.status, json);
    return json;
  }

  // ---------------- auth (zero-knowledge) ----------------
  async register(handle) {
    const ch = await this.#http('POST', '/v1/auth/challenge', {}, { auth: false });
    const proof = prove(this.keys.identitySecret, ch.nonce, `register|${handle}|${this.keys.encPubkey}`);
    const out = await this.#http(
      'POST',
      '/v1/auth/register',
      { handle, identityPubkey: this.keys.identityPubkey, encPubkey: this.keys.encPubkey, challengeId: ch.challengeId, proof },
      { auth: false },
    );
    this.token = out.token;
    this.user = out.user;
    return out.user;
  }

  async login() {
    const ch = await this.#http('POST', '/v1/auth/challenge', {}, { auth: false });
    const proof = prove(this.keys.identitySecret, ch.nonce, 'login');
    const out = await this.#http(
      'POST',
      '/v1/auth/login',
      { identityPubkey: this.keys.identityPubkey, challengeId: ch.challengeId, proof },
      { auth: false },
    );
    this.token = out.token;
    this.user = out.user;
    return out.user;
  }

  // ---------------- social graph ----------------
  me() { return this.#http('GET', '/v1/users/me'); }
  profile(handle) { return this.#http('GET', `/v1/users/${handle}`); }
  follow(handle) { return this.#http('POST', `/v1/users/${handle}/follow`); }
  unfollow(handle) { return this.#http('DELETE', `/v1/users/${handle}/follow`); }
  async followers() { return (await this.#http('GET', '/v1/users/me/followers')).followers; }

  // ---------------- encrypted posts ----------------
  /** Encrypt for yourself + all current followers, sign, upload. */
  async post(text) {
    const followers = await this.followers();
    const recipients = [{ id: this.user.id, encPubkey: this.keys.encPubkey }, ...followers.map((f) => ({ id: f.id, encPubkey: f.encPubkey }))];
    const id = crypto.randomUUID();
    const { ciphertext, envelopes } = encryptForRecipients(id, JSON.stringify({ text, ts: Date.now() }), recipients);
    const signature = signParts(this.keys.identitySecret, ['post', id, ciphertext]);
    return this.#http('POST', '/v1/posts', { id, ciphertext, signature, envelopes });
  }

  #decryptPost(p) {
    try {
      const pinned = this.pinned.get(p.author.handle);
      if (!pinned) this.pinned.set(p.author.handle, p.author.identityPubkey);
      const keyOk = !pinned || pinned === p.author.identityPubkey;
      const verified = keyOk && verifyParts(p.author.identityPubkey, p.signature, ['post', p.id, p.ciphertext]);
      const plain = JSON.parse(decryptItem(p.id, p.ciphertext, p.wrappedKey, this.keys.encSecret, this.keys.encPubkey));
      return { id: p.id, seq: p.seq, author: p.author.handle, text: plain.text, createdAt: p.createdAt, verified };
    } catch {
      return { id: p.id, seq: p.seq, author: p.author.handle, error: 'undecryptable' };
    }
  }

  async feed({ before, limit } = {}) {
    const qs = new URLSearchParams({ ...(before ? { before } : {}), ...(limit ? { limit } : {}) });
    const out = await this.#http('GET', `/v1/posts/feed?${qs}`);
    return { posts: out.posts.map((p) => this.#decryptPost(p)), nextBefore: out.nextBefore };
  }

  async getPost(id) { return this.#decryptPost(await this.#http('GET', `/v1/posts/${id}`)); }
  rawPost(id) { return this.#http('GET', `/v1/posts/${id}`); }
  deletePost(id) { return this.#http('DELETE', `/v1/posts/${id}`); }

  /** Give a (new) follower access to one of your older posts. Decrypts the content key locally, re-wraps it. */
  async grantAccess(postId, handle) {
    const mine = await this.rawPost(postId);
    const contentKey = decryptContentKey(mine.wrappedKey, this.keys.encSecret, this.keys.encPubkey, postId);
    const target = await this.profile(handle);
    const envelopes = { [target.id]: wrapContentKeyFor(contentKey, target.encPubkey, postId) };
    return this.#http('POST', `/v1/posts/${postId}/envelopes`, { envelopes });
  }

  // ---------------- encrypted DMs ----------------
  async sendMessage(handle, text) {
    const to = await this.profile(handle);
    const id = crypto.randomUUID();
    const { ciphertext, envelopes } = encryptForRecipients(id, text, [
      { id: this.user.id, encPubkey: this.keys.encPubkey },
      { id: to.id, encPubkey: to.encPubkey },
    ]);
    const signature = signParts(this.keys.identitySecret, ['msg', id, to.id, ciphertext]);
    return this.#http('POST', '/v1/messages', {
      id, recipientId: to.id, ciphertext, signature,
      keyForSender: envelopes[this.user.id],
      keyForRecipient: envelopes[to.id],
    });
  }

  async messages({ with: peer, before, limit } = {}) {
    const qs = new URLSearchParams({ ...(peer ? { with: peer } : {}), ...(before ? { before } : {}), ...(limit ? { limit } : {}) });
    const out = await this.#http('GET', `/v1/messages?${qs}`);
    return out.messages.map((m) => {
      try {
        const pinned = this.pinned.get(m.sender.handle);
        if (!pinned) this.pinned.set(m.sender.handle, m.sender.identityPubkey);
        const verified =
          (!pinned || pinned === m.sender.identityPubkey) &&
          verifyParts(m.sender.identityPubkey, m.signature, ['msg', m.id, m.recipient.id, m.ciphertext]);
        return {
          id: m.id, seq: m.seq, from: m.sender.handle, to: m.recipient.handle, createdAt: m.createdAt, verified,
          text: decryptItem(m.id, m.ciphertext, m.wrappedKey, this.keys.encSecret, this.keys.encPubkey),
        };
      } catch {
        return { id: m.id, seq: m.seq, from: m.sender.handle, to: m.recipient.handle, error: 'undecryptable' };
      }
    });
  }

  // ---------------- SocialFi ----------------
  wallet() { return this.#http('GET', '/v1/wallet'); }
  faucet() { return this.#http('POST', '/v1/wallet/faucet'); }
  tip({ postId, toHandle, amount, idempotencyKey = crypto.randomUUID() }) {
    return this.#http('POST', '/v1/wallet/tips', { postId, toHandle, amount, idempotencyKey });
  }
}
