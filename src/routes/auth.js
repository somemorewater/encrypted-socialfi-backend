import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { tx } from '../db.js';
import { verify } from '../crypto/zk.js';
import { issueToken } from '../middleware/auth.js';
import { conflict, parse, unauthorized } from '../errors.js';
import * as S from '../schemas.js';

const registerBody = z.object({
  handle: S.handle,
  identityPubkey: S.identityPubkey,
  encPubkey: S.encPubkey,
  challengeId: S.uuid,
  proof: S.proof,
});
const loginBody = z.object({ identityPubkey: S.identityPubkey, challengeId: S.uuid, proof: S.proof });

export function authRoutes({ pool, config }) {
  const r = Router();

  /** Step 1: get a single-use nonce. Any replica can issue it; any replica can consume it. */
  r.post('/challenge', async (_req, res) => {
    const { rows } = await pool.query(
      `INSERT INTO auth_challenges (nonce, expires_at) VALUES ($1, now() + make_interval(secs => $2))
       RETURNING id, nonce, expires_at`,
      [crypto.randomBytes(32).toString('hex'), config.challengeTtlSeconds],
    );
    res.status(201).json({ challengeId: rows[0].id, nonce: rows[0].nonce, expiresAt: rows[0].expires_at });
  });

  // Atomic consume: DELETE ... RETURNING guarantees a nonce can be used at most once, cluster-wide.
  const consumeChallenge = async (db, id) => {
    const { rows } = await db.query(
      'DELETE FROM auth_challenges WHERE id = $1 AND expires_at > now() RETURNING nonce',
      [id],
    );
    return rows[0]?.nonce ?? null;
  };

  /**
   * Register: the client proves (in zero knowledge) that it holds the secret key for `identityPubkey`.
   * The proof context binds the chosen handle AND encryption key, so neither can be swapped in transit.
   */
  r.post('/register', async (req, res) => {
    const b = parse(registerBody, req.body);
    const user = await tx(pool, async (db) => {
      const nonce = await consumeChallenge(db, b.challengeId);
      if (!nonce) throw unauthorized('Challenge invalid, expired or already used');
      if (!verify(b.identityPubkey, b.proof, nonce, `register|${b.handle}|${b.encPubkey}`)) {
        throw unauthorized('Invalid proof');
      }
      try {
        const { rows } = await db.query(
          `INSERT INTO users (handle, identity_pubkey, enc_pubkey) VALUES ($1,$2,$3)
           RETURNING id, handle, identity_pubkey, enc_pubkey, created_at`,
          [b.handle, b.identityPubkey, b.encPubkey],
        );
        await db.query('INSERT INTO accounts (user_id) VALUES ($1)', [rows[0].id]);
        return rows[0];
      } catch (e) {
        if (e.code === '23505') throw conflict('Handle or identity key already registered', 'already_registered');
        throw e;
      }
    });
    res.status(201).json({ token: issueToken(config, user.id), user: publicUser(user) });
  });

  /** Login = a fresh ZK proof of key knowledge. No password, no secret ever sent to the server. */
  r.post('/login', async (req, res) => {
    const b = parse(loginBody, req.body);
    const nonce = await consumeChallenge(pool, b.challengeId); // burn the nonce even if the user is unknown
    if (!nonce) throw unauthorized('Challenge invalid, expired or already used');
    const { rows } = await pool.query(
      'SELECT id, handle, identity_pubkey, enc_pubkey, created_at FROM users WHERE identity_pubkey = $1',
      [b.identityPubkey],
    );
    // Same error for "unknown key" and "bad proof": no account enumeration.
    if (!rows[0] || !verify(b.identityPubkey, b.proof, nonce, 'login')) throw unauthorized('Authentication failed');
    res.json({ token: issueToken(config, rows[0].id), user: publicUser(rows[0]) });
  });

  return r;
}

export const publicUser = (u) => ({
  id: u.id,
  handle: u.handle,
  identityPubkey: u.identity_pubkey,
  encPubkey: u.enc_pubkey,
  createdAt: u.created_at,
});
