// Zero-knowledge proof of knowledge of a secret key: non-interactive Schnorr (Fiat–Shamir) over secp256k1.
//
//   Public key   P = x·G                      (x is the user's secret; it never leaves the client)
//   Prover:      k <- random,  R = k·G
//                c = H(domain, P, R, nonce, context)  mod n
//                s = k + c·x   mod n          -> proof = (R, s)
//   Verifier:    c = H(...);  accept iff  s·G == R + c·P
//
// The proof reveals nothing about x (honest-verifier zero-knowledge), and is bound to a
// single-use server nonce (anti-replay) and to a `context` string (anti-substitution).
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils';

const Point = secp256k1.ProjectivePoint;
const n = secp256k1.CURVE.n;
const DOMAIN = utf8ToBytes('socialfi-zk-schnorr-v1');

const bytesToBigInt = (b) => BigInt('0x' + bytesToHex(b));
const bigIntTo32 = (x) => hexToBytes(x.toString(16).padStart(64, '0'));
const lp = (bytes) => concatBytes(Uint8Array.of(bytes.length >> 8, bytes.length & 0xff), bytes); // length-prefix

function challengeScalar(pubBytes, rBytes, nonceHex, context) {
  const h = sha256(
    concatBytes(lp(DOMAIN), lp(pubBytes), lp(rBytes), lp(hexToBytes(nonceHex)), lp(utf8ToBytes(context))),
  );
  return bytesToBigInt(h) % n;
}

export function generateIdentity() {
  const secret = secp256k1.utils.randomPrivateKey();
  return { secret: bytesToHex(secret), pub: bytesToHex(secp256k1.getPublicKey(secret, true)) };
}

export function publicKeyFromSecret(secretHex) {
  return bytesToHex(secp256k1.getPublicKey(hexToBytes(secretHex), true));
}

/** Client side: prove knowledge of `secretHex` for the given server nonce + context. */
export function prove(secretHex, nonceHex, context) {
  const x = bytesToBigInt(hexToBytes(secretHex));
  const pubBytes = secp256k1.getPublicKey(hexToBytes(secretHex), true);
  const k = bytesToBigInt(secp256k1.utils.randomPrivateKey());
  const rBytes = Point.BASE.multiply(k).toRawBytes(true);
  const c = challengeScalar(pubBytes, rBytes, nonceHex, context);
  const s = (k + c * x) % n;
  return { R: bytesToHex(rBytes), s: bytesToHex(bigIntTo32(s)) };
}

/** Server side: verify a proof for `pubHex`. Never throws on malformed input; returns false. */
export function verify(pubHex, proof, nonceHex, context) {
  try {
    const pubBytes = hexToBytes(pubHex);
    const P = Point.fromHex(pubBytes); // throws if not on curve
    if (P.equals(Point.ZERO)) return false;
    const rBytes = hexToBytes(proof.R);
    const R = Point.fromHex(rBytes);
    const s = bytesToBigInt(hexToBytes(proof.s));
    if (s <= 0n || s >= n) return false;
    const c = challengeScalar(P.toRawBytes(true), R.toRawBytes(true), nonceHex, context);
    if (c === 0n) return false; // negligible probability; also avoids a zero-scalar multiply
    return Point.BASE.multiply(s).equals(R.add(P.multiply(c)));
  } catch {
    return false;
  }
}

// ---- Ordinary signatures with the same identity key (content authenticity) ----

const digest = (parts) => sha256(concatBytes(...parts.map((p) => lp(utf8ToBytes(String(p))))));

export function signParts(secretHex, parts) {
  return secp256k1.sign(digest(parts), hexToBytes(secretHex)).toCompactHex();
}

export function verifyParts(pubHex, sigHex, parts) {
  try {
    return secp256k1.verify(sigHex, digest(parts), pubHex);
  } catch {
    return false;
  }
}
