// Integration tests. Requires a reachable PostgreSQL: DATABASE_URL=postgres://... npm test
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { migrate } from '../src/migrate.js';
import { createApp } from '../src/app.js';
import { SocialFiClient, generateKeys, ApiError } from '../sdk/client.js';
import { prove } from '../src/crypto/zk.js';
import { signParts } from '../src/crypto/zk.js';
import { encryptForRecipients } from '../sdk/e2ee.js';

let pool, server, baseUrl;
const rid = () => crypto.randomBytes(4).toString('hex');

before(async () => {
  const config = { ...loadConfig(), rateLimitPerMin: 100000, authRateLimitPerMin: 100000, faucetEnabled: true };
  pool = createPool(config.databaseUrl);
  await migrate(pool);
  server = createApp({ pool, config }).listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  server?.close();
  await pool?.end();
});

async function user(prefix) {
  const c = new SocialFiClient({ baseUrl, keys: generateKeys() });
  await c.register(`${prefix}_${rid()}`);
  return c;
}
const expectStatus = async (promise, status, code) => {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof ApiError, String(e));
    assert.equal(e.status, status, `${e.status} ${e.message}`);
    if (code) assert.equal(e.code, code);
    return true;
  });
};
const raw = (path, opts) => fetch(baseUrl + path, { headers: { 'content-type': 'application/json' }, ...opts });

test('health check', async () => {
  const r = await raw('/healthz');
  assert.equal(r.status, 200);
});

test('auth: register + login via ZK proof; challenge is single-use', async () => {
  const keys = generateKeys();
  const c = new SocialFiClient({ baseUrl, keys });
  await c.register(`zk_${rid()}`);
  const c2 = new SocialFiClient({ baseUrl, keys });
  await c2.login();
  assert.equal(c2.user.id, c.user.id);
  assert.equal((await c2.me()).handle, c.user.handle);

  // Replay: reuse one challenge twice
  const ch = await (await raw('/v1/auth/challenge', { method: 'POST', body: '{}' })).json();
  const proof = prove(keys.identitySecret, ch.nonce, 'login');
  const body = JSON.stringify({ identityPubkey: keys.identityPubkey, challengeId: ch.challengeId, proof });
  assert.equal((await raw('/v1/auth/login', { method: 'POST', body })).status, 200);
  assert.equal((await raw('/v1/auth/login', { method: 'POST', body })).status, 401, 'replayed proof must fail');
});

test('auth: proof by a different key, unknown key, and bad registration are rejected', async () => {
  const victim = await user('victim');
  const attacker = generateKeys();
  const ch = await (await raw('/v1/auth/challenge', { method: 'POST', body: '{}' })).json();
  // attacker proves with their own secret but claims the victim's public key
  const forged = prove(attacker.identitySecret, ch.nonce, 'login');
  const r = await raw('/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ identityPubkey: victim.keys.identityPubkey, challengeId: ch.challengeId, proof: forged }),
  });
  assert.equal(r.status, 401);

  // Proof-of-possession at registration: can't register someone else's public key
  const ch2 = await (await raw('/v1/auth/challenge', { method: 'POST', body: '{}' })).json();
  const bad = prove(attacker.identitySecret, ch2.nonce, `register|stolen_${rid()}|${attacker.encPubkey}`);
  const r2 = await raw('/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      handle: `stolen_${rid()}`, identityPubkey: victim.keys.identityPubkey, encPubkey: attacker.encPubkey,
      challengeId: ch2.challengeId, proof: bad,
    }),
  });
  assert.equal(r2.status, 401);

  // Duplicate handle -> 409
  const dup = new SocialFiClient({ baseUrl, keys: generateKeys() });
  await expectStatus(dup.register(victim.user.handle), 409);
});

test('auth: protected routes require a token', async () => {
  assert.equal((await raw('/v1/posts/feed')).status, 401);
  assert.equal((await raw('/v1/posts/feed', { headers: { authorization: 'Bearer nope' } })).status, 401);
});

test('E2EE posts: followers read, strangers cannot; DB holds only ciphertext', async () => {
  const alice = await user('alice');
  const bob = await user('bob');
  const carol = await user('carol');
  await bob.follow(alice.user.handle);

  const secret = `top secret ${rid()}`;
  const { id } = await alice.post(secret);

  const bobFeed = (await bob.feed()).posts;
  assert.equal(bobFeed[0].text, secret);
  assert.equal(bobFeed[0].verified, true);
  assert.equal((await alice.feed()).posts[0].text, secret, 'author reads own post');

  assert.deepEqual((await carol.feed()).posts, []);
  await expectStatus(carol.getPost(id), 404);

  const { rows } = await pool.query('SELECT ciphertext FROM posts WHERE id=$1', [id]);
  assert.ok(!Buffer.from(rows[0].ciphertext, 'base64').toString('utf8').includes(secret));
  assert.ok(!rows[0].ciphertext.includes(secret));
});

test('E2EE posts: late follower gets access only after author grants it', async () => {
  const alice = await user('alice');
  const dave = await user('dave');
  const { id } = await alice.post('before dave followed');
  await dave.follow(alice.user.handle);
  assert.deepEqual((await dave.feed()).posts, []);
  await alice.grantAccess(id, dave.user.handle);
  assert.equal((await dave.feed()).posts[0].text, 'before dave followed');
});

test('posts: server enforces audience, signatures and ownership', async () => {
  const alice = await user('alice');
  const mallory = await user('mallory');
  const bob = await user('bob');

  // envelope to a non-follower is refused
  const id = crypto.randomUUID();
  const { ciphertext, envelopes } = encryptForRecipients(id, 'x', [
    { id: alice.user.id, encPubkey: alice.keys.encPubkey },
    { id: mallory.user.id, encPubkey: mallory.keys.encPubkey },
  ]);
  const signature = signParts(alice.keys.identitySecret, ['post', id, ciphertext]);
  const post = (body) => fetch(baseUrl + '/v1/posts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${alice.token}` },
    body: JSON.stringify(body),
  });
  assert.equal((await post({ id, ciphertext, signature, envelopes })).status, 403);

  // bad signature (signed by someone else)
  const forged = signParts(mallory.keys.identitySecret, ['post', id, ciphertext]);
  const r = await post({ id, ciphertext, signature: forged, envelopes: { [alice.user.id]: envelopes[alice.user.id] } });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error.code, 'bad_signature');

  // only author may delete / grant
  await bob.follow(alice.user.handle);
  const { id: pid } = await alice.post('mine');
  await expectStatus(bob.deletePost(pid), 404);
  await expectStatus(bob.grantAccess(pid, alice.user.handle), 403);
  await alice.deletePost(pid);
  assert.ok(signature);
});

test('E2EE DMs: only the two parties can read', async () => {
  const a = await user('ann');
  const b = await user('ben');
  const c = await user('cat');
  await a.sendMessage(b.user.handle, 'psst');
  await b.sendMessage(a.user.handle, 'hi back');
  assert.deepEqual((await b.messages({ with: a.user.handle })).map((m) => m.text).sort(), ['hi back', 'psst']);
  assert.ok((await a.messages()).every((m) => m.verified));
  assert.deepEqual(await c.messages(), []);
});

test('wallet: faucet, tipping, idempotency, insufficient funds', async () => {
  const alice = await user('alice');
  const bob = await user('bob');
  await bob.follow(alice.user.handle);
  const { id } = await alice.post('tip me');

  assert.equal((await bob.faucet()).balance, 1000);
  await expectStatus(bob.faucet(), 429);

  const key = crypto.randomUUID();
  const t1 = await bob.tip({ postId: id, amount: 300, idempotencyKey: key });
  assert.equal(t1.replay, false);
  const t2 = await bob.tip({ postId: id, amount: 300, idempotencyKey: key });
  assert.equal(t2.replay, true);
  assert.equal(t2.id, t1.id);
  assert.equal((await bob.wallet()).balance, 700);
  assert.equal((await alice.wallet()).balance, 300);
  await expectStatus(bob.tip({ postId: id, amount: 301, idempotencyKey: key }), 422, 'idempotency_mismatch');

  await expectStatus(bob.tip({ toHandle: alice.user.handle, amount: 5000 }), 402, 'insufficient_funds');
  await expectStatus(bob.tip({ toHandle: bob.user.handle, amount: 1 }), 400);
  // strangers can't tip a post they can't read
  const eve = await user('eve');
  await eve.faucet();
  await expectStatus(eve.tip({ postId: id, amount: 1 }), 404);
});

test('wallet: concurrent tips never overdraw and conserve total supply', async () => {
  const alice = await user('alice');
  const bob = await user('bob');
  await bob.faucet(); // 1000
  const results = await Promise.allSettled(
    Array.from({ length: 12 }, () => bob.tip({ toHandle: alice.user.handle, amount: 200 })),
  );
  const ok = results.filter((r) => r.status === 'fulfilled').length;
  assert.equal(ok, 5);
  assert.equal((await bob.wallet()).balance, 0);
  assert.equal((await alice.wallet()).balance, 1000);
});

test('validation: malformed input returns 400 with details', async () => {
  const r = await raw('/v1/auth/register', { method: 'POST', body: JSON.stringify({ handle: 'X' }) });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error.code, 'validation_error');
  const r2 = await raw('/v1/auth/register', { method: 'POST', body: '{not json' });
  assert.equal(r2.status, 400);
});
