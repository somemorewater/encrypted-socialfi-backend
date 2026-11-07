// End-to-end walkthrough against a running server:  npm start  (other terminal)  &&  npm run demo
import crypto from 'node:crypto';
import pg from 'pg';
import { SocialFiClient, generateKeys } from '../sdk/client.js';

const BASE = process.env.BASE_URL ?? 'http://localhost:3000';
const suffix = crypto.randomBytes(3).toString('hex');
const log = (s) => console.log(`\n\u2500\u2500 ${s}`);

const mk = (name) => new SocialFiClient({ baseUrl: BASE, keys: generateKeys() });
const [alice, bob, carol] = [mk('alice'), mk('bob'), mk('carol')];

log('1. Register with a zero-knowledge proof (no password, no secret leaves the device)');
await alice.register(`alice_${suffix}`);
await bob.register(`bob_${suffix}`);
await carol.register(`carol_${suffix}`);
console.log('registered:', alice.user.handle, bob.user.handle, carol.user.handle);

log('2. Log in again with a fresh proof');
await alice.login();
console.log('alice logged in, token issued');

log('3. Bob follows Alice; Alice posts (encrypted for herself + her followers)');
await bob.follow(alice.user.handle);
const created = await alice.post('gm! first encrypted post from Alice \u{1F512}');
console.log('post id:', created.id);

log('4. Bob (follower) can read it; Carol (not a follower) cannot');
console.log('bob feed  :', (await bob.feed()).posts.map((p) => `${p.author}: ${p.text} [verified=${p.verified}]`));
console.log('carol feed:', (await carol.feed()).posts);

if (process.env.DATABASE_URL) {
  log('5. What the database actually holds for that post');
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const { rows } = await pool.query('SELECT left(ciphertext, 60) AS ciphertext_prefix FROM posts WHERE id=$1', [created.id]);
  console.log(rows[0], '(no plaintext anywhere)');
  await pool.end();
}

log('6. Carol follows later \u2192 Alice grants her access to the older post (re-wraps the key client-side)');
await carol.follow(alice.user.handle);
await alice.grantAccess(created.id, carol.user.handle);
console.log('carol feed:', (await carol.feed()).posts.map((p) => p.text));

log('7. Encrypted DM');
await bob.sendMessage(alice.user.handle, 'hey Alice, loved the post');
console.log('alice inbox:', (await alice.messages({ with: bob.user.handle })).map((m) => `${m.from}: ${m.text}`));

log('8. Tipping (SocialFi)');
await bob.faucet();
const tip = await bob.tip({ postId: created.id, amount: 250 });
console.log('tip:', tip.amount, '| bob balance:', (await bob.wallet()).balance, '| alice balance:', (await alice.wallet()).balance);
