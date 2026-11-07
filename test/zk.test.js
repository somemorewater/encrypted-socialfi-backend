import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { generateIdentity, prove, verify, signParts, verifyParts } from '../src/crypto/zk.js';
import { generateEncryptionKeypair, encryptForRecipients, decryptItem } from '../sdk/e2ee.js';

const nonce = () => crypto.randomBytes(32).toString('hex');

test('ZK: valid proof verifies', () => {
  const id = generateIdentity();
  const n = nonce();
  assert.equal(verify(id.pub, prove(id.secret, n, 'login'), n, 'login'), true);
});

test('ZK: wrong key, wrong nonce, wrong context, tampered proof all fail', () => {
  const a = generateIdentity();
  const b = generateIdentity();
  const n = nonce();
  const p = prove(a.secret, n, 'login');
  assert.equal(verify(b.pub, p, n, 'login'), false, 'other public key');
  assert.equal(verify(a.pub, p, nonce(), 'login'), false, 'different nonce (replay)');
  assert.equal(verify(a.pub, p, n, 'register|x|y'), false, 'different context');
  const flipped = { ...p, s: p.s.slice(0, -1) + (p.s.endsWith('0') ? '1' : '0') };
  assert.equal(verify(a.pub, flipped, n, 'login'), false, 'tampered s');
  assert.equal(verify(a.pub, { R: 'zz', s: p.s }, n, 'login'), false, 'garbage R');
  assert.equal(verify(a.pub, { R: p.R, s: '00'.repeat(32) }, n, 'login'), false, 's = 0');
});

test('ZK: proofs are randomised (two proofs for same statement differ)', () => {
  const id = generateIdentity();
  const n = nonce();
  assert.notEqual(prove(id.secret, n, 'login').R, prove(id.secret, n, 'login').R);
});

test('signatures: verify and reject tampering', () => {
  const id = generateIdentity();
  const sig = signParts(id.secret, ['post', 'id1', 'ct']);
  assert.equal(verifyParts(id.pub, sig, ['post', 'id1', 'ct']), true);
  assert.equal(verifyParts(id.pub, sig, ['post', 'id1', 'ct2']), false);
});

test('E2EE: only intended recipients can decrypt; AAD binds ciphertext to item id', () => {
  const alice = generateEncryptionKeypair();
  const bob = generateEncryptionKeypair();
  const eve = generateEncryptionKeypair();
  const { ciphertext, envelopes } = encryptForRecipients('item-1', 'secret text', [
    { id: 'alice', encPubkey: alice.pub },
    { id: 'bob', encPubkey: bob.pub },
  ]);
  assert.equal(decryptItem('item-1', ciphertext, envelopes.bob, bob.secret, bob.pub), 'secret text');
  assert.throws(() => decryptItem('item-1', ciphertext, envelopes.bob, eve.secret, eve.pub));
  assert.throws(() => decryptItem('item-2', ciphertext, envelopes.bob, bob.secret, bob.pub), /./, 'wrong item id');
  const tampered = Buffer.from(ciphertext, 'base64');
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decryptItem('item-1', tampered.toString('base64'), envelopes.bob, bob.secret, bob.pub));
});
