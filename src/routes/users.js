import { Router } from 'express';
import { notFound, badRequest, parse } from '../errors.js';
import { handle } from '../schemas.js';
import { publicUser } from './auth.js';

export function userRoutes({ pool, config }) {
  const r = Router();

  const findByHandle = async (db, h) => {
    const { rows } = await db.query(
      'SELECT id, handle, identity_pubkey, enc_pubkey, created_at FROM users WHERE handle = $1',
      [parse(handle, h)],
    );
    if (!rows[0]) throw notFound('User not found');
    return rows[0];
  };

  r.get('/me', async (req, res) => {
    const { rows } = await pool.query(
      `SELECT u.id, u.handle, u.identity_pubkey, u.enc_pubkey, u.created_at,
              (SELECT count(*) FROM follows WHERE followee_id = u.id)::int AS followers,
              (SELECT count(*) FROM follows WHERE follower_id = u.id)::int AS following
       FROM users u WHERE u.id = $1`,
      [req.userId],
    );
    if (!rows[0]) throw notFound('User not found');
    res.json({ ...publicUser(rows[0]), followers: rows[0].followers, following: rows[0].following });
  });

  /** Audience for new posts: followers' ids + encryption keys. Clients wrap content keys for these. */
  r.get('/me/followers', async (req, res) => {
    const { rows } = await pool.query(
      `SELECT u.id, u.handle, u.identity_pubkey, u.enc_pubkey, u.created_at
       FROM follows f JOIN users u ON u.id = f.follower_id
       WHERE f.followee_id = $1 ORDER BY f.created_at LIMIT $2`,
      [req.userId, config.maxAudience],
    );
    res.json({ followers: rows.map(publicUser) });
  });

  /** Public directory lookup (public keys only). */
  r.get('/:handle', async (req, res) => {
    res.json(publicUser(await findByHandle(pool, req.params.handle)));
  });

  r.post('/:handle/follow', async (req, res) => {
    const target = await findByHandle(pool, req.params.handle);
    if (target.id === req.userId) throw badRequest('You cannot follow yourself');
    await pool.query(
      'INSERT INTO follows (follower_id, followee_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [req.userId, target.id],
    );
    res.status(204).end();
  });

  r.delete('/:handle/follow', async (req, res) => {
    const target = await findByHandle(pool, req.params.handle);
    await pool.query('DELETE FROM follows WHERE follower_id=$1 AND followee_id=$2', [req.userId, target.id]);
    res.status(204).end();
  });

  return r;
}
