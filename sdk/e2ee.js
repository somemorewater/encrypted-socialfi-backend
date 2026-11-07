// Client-side end-to-end encryption primitives (Node's built-in crypto only).
//
//  content  : AES-256-GCM with a fresh random 256-bit key per item
//  key wrap : ephemeral X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM  (one envelope per recipient)
//
// Wire formats (all base64):
//   ciphertext  = iv(12) || tag(16) || ct
//   wrapped key = ephemeralPub(32) || iv(12) || tag(16) || ct(32)
import crypto from 'node:crypto';

const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');

const privKeyObj = (hex) =>
  crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
const pubKeyObj = (hex) =>
  crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });

export function generateEncryptionKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    secret: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
  };
}

function aesGcmEncrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

function aesGcmDecrypt(key, blob, aad) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

const hkdf = (shared, ephPub, recipPub) =>
  Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([ephPub, recipPub]), 'socialfi-v1-wrap', 32));

function wrapKey(contentKey, recipientEncPubHex, itemId) {
  const eph = crypto.generateKeyPairSync('x25519');
  const ephPub = eph.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubKeyObj(recipientEncPubHex) });
  const kek = hkdf(shared, ephPub, Buffer.from(recipientEncPubHex, 'hex'));
  return Buffer.concat([ephPub, aesGcmEncrypt(kek, contentKey, `socialfi:wrap:${itemId}`)]).toString('base64');
}

function unwrapKey(wrappedB64, myEncSecretHex, myEncPubHex, itemId) {
  const buf = Buffer.from(wrappedB64, 'base64');
  const ephPub = buf.subarray(0, 32);
  const shared = crypto.diffieHellman({
    privateKey: privKeyObj(myEncSecretHex),
    publicKey: pubKeyObj(ephPub.toString('hex')),
  });
  const kek = hkdf(shared, ephPub, Buffer.from(myEncPubHex, 'hex'));
  return aesGcmDecrypt(kek, buf.subarray(32), `socialfi:wrap:${itemId}`);
}

/**
 * Encrypt `plaintext` once and wrap the content key for every recipient.
 * @param recipients  [{ id, encPubkey }]
 * @returns { ciphertext, envelopes: { [userId]: wrappedKeyB64 } }
 */
export function encryptForRecipients(itemId, plaintext, recipients) {
  const contentKey = crypto.randomBytes(32);
  const ciphertext = aesGcmEncrypt(contentKey, Buffer.from(plaintext, 'utf8'), `socialfi:content:${itemId}`).toString('base64');
  const envelopes = {};
  for (const r of recipients) envelopes[r.id] = wrapKey(contentKey, r.encPubkey, itemId);
  return { ciphertext, envelopes };
}

/** Wrap an existing content key for an additional recipient (used when granting access later). */
export function decryptContentKey(wrappedB64, myEncSecretHex, myEncPubHex, itemId) {
  return unwrapKey(wrappedB64, myEncSecretHex, myEncPubHex, itemId);
}

export function wrapContentKeyFor(contentKey, recipientEncPubHex, itemId) {
  return wrapKey(contentKey, recipientEncPubHex, itemId);
}

export function decryptItem(itemId, ciphertextB64, wrappedKeyB64, myEncSecretHex, myEncPubHex) {
  const contentKey = unwrapKey(wrappedKeyB64, myEncSecretHex, myEncPubHex, itemId);
  return aesGcmDecrypt(contentKey, Buffer.from(ciphertextB64, 'base64'), `socialfi:content:${itemId}`).toString('utf8');
}
