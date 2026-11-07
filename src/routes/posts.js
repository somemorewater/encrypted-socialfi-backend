import { Router } from 'express';
import { z } from 'zod';
import { tx } from '../db.js';
import { verifyParts } from '../crypto/zk.js';
import { badRequest, forbidden, notFound, conflict, parse } from '../errors.js';
import * as S from '../schemas.js';

const envelopes = z
  .record(S.uuid, S.wrappedKey)
  .refine((o) => Object.keys(o).length >= 1, 'at least one envelope required');

const createBody = z.object({
  id: S.uuid,
  ciphertext: S.ciphertext,
  signature: S.signature,
  envelopes,
});
const grantBody = z.object({ envelopes });

const postDto = (row) => ({
  id: row.id,
  seq: Number(row.seq),
  author: { id: row.author_id, handle: row.author_handle, identityPubkey: row.author_identity_pubkey },
  ciphertext: row.ciphertext,
  signature: row.signature,
  wrappedKey: row.wrapped_key,
  createdAt: row.created_at,
});

const SELECT_VISIBLE = `
  SELECT p.id, p.seq, p.ciphertext, p.signature, p.created_at, p.author_id,
         u.handle AS author_handle, u.identity_pubkey AS author_identity_pubkey, k.wrapped_key
  FROM post_keys k
  JOIN posts p ON p.id = k.post_id
  JOIN users u ON u.id = p.author_id`;

export function postRoutes({ pool, config }) {
  const r = Router();

  /** Every recipient must be the author or one of the author's followers. */
  async function assertAudience(db, authorId, recipientIds) {
    if (recipientIds.length > config.maxAudience) throw badRequest(`Max ${config.maxAudience} recipients`);
    const others = recipientIds.filter((id) => id !== authorId);
    if (others.length === 0) return;
    const { rows } = await db.query(
      'SELECT follower_id FROM follows WHERE followee_id = $1 AND follower_id = ANY($2::uuid[])',
      [authorId, others],
    );
    if (rows.length !== others.length) throw forbidden('Envelopes may only target your followers');
  }

  const insertEnvelopes = (db, postId, env) =>
    db.query(
      `INSERT INTO post_keys (post_id, recipient_id, wrapped_key)
       SELECT $1, * FROM unnest($2::uuid[], $3::text[]) ON CONFLICT DO NOTHING`,
      [postId, Object.keys(env), Object.values(env)],
    );

  /** Store an encrypted post. The server sees only ciphertext + per-recipient wrapped keys. */
  r.post('/', async (req, res) => {
    const b = parse(createBody, req.body);
    if (!b.envelopes[req.userId]) throw badRequest('Include an envelope for yourself so you can read your own post');
    const created = await tx(pool, async (db) => {
      const { rows: u } = await db.query('SELECT identity_pubkey FROM users WHERE id=$1', [req.userId]);
      if (!u[0]) throw notFound('User not found');
      // Authenticity: the post must be signed by the author's identity key.
      if (!verifyParts(u[0].identity_pubkey, b.signature, ['post', b.id, b.ciphertext])) {
        throw badRequest('Invalid signature', 'bad_signature');
      }
      await assertAudience(db, req.userId, Object.keys(b.envelopes));
      try {
        const { rows } = await db.query(
          'INSERT INTO posts (id, author_id, ciphertext, signature) VALUES ($1,$2,$3,$4) RETURNING seq, created_at',
          [b.id, req.userId, b.ciphertext, b.signature],
        );
        await insertEnvelopes(db, b.id, b.envelopes);
        return rows[0];
      } catch (e) {
        if (e.code === '23505') throw conflict('Post id already exists');
        throw e;
      }
    });
    res.status(201).json({ id: b.id, seq: Number(created.seq), createdAt: created.created_at });
  });

  /** Home feed: every post for which I hold a wrapped key. Access control == key possession. */
  r.get('/feed', async (req, res) => {
    const q = parse(S.cursor, req.query);
    const { rows } = await pool.query(
      `${SELECT_VISIBLE}
       WHERE k.recipient_id = $1 AND ($2::bigint IS NULL OR p.seq < $2)
       ORDER BY p.seq DESC LIMIT $3`,
      [req.userId, q.before ?? null, q.limit],
    );
    const posts = rows.map(postDto);
    res.json({ posts, nextBefore: posts.length === q.limit ? posts[posts.length - 1].seq : null });
  });

  r.get('/by/:handle', async (req, res) => {
    const q = parse(S.cursor, req.query);
    const { rows } = await pool.query(
      `${SELECT_VISIBLE}
       WHERE k.recipient_id = $1 AND u.handle = $2 AND ($3::bigint IS NULL OR p.seq < $3)
       ORDER BY p.seq DESC LIMIT $4`,
      [req.userId, parse(S.handle, req.params.handle), q.before ?? null, q.limit],
    );
    const posts = rows.map(postDto);
    res.json({ posts, nextBefore: posts.length === q.limit ? posts[posts.length - 1].seq : null });
  });

  r.get('/:id', async (req, res) => {
    const { rows } = await pool.query(`${SELECT_VISIBLE} WHERE k.recipient_id = $1 AND p.id = $2`, [
      req.userId,
      parse(S.uuid, req.params.id),
    ]);
    if (!rows[0]) throw notFound('Post not found'); // same answer whether it exists or you lack access
    res.json(postDto(rows[0]));
  });

  /** Author grants access to more followers (e.g. someone who followed after posting). */
  r.post('/:id/envelopes', async (req, res) => {
    const id = parse(S.uuid, req.params.id);
    const { envelopes: env } = parse(grantBody, req.body);
    await tx(pool, async (db) => {
      const { rows } = await db.query('SELECT author_id FROM posts WHERE id=$1', [id]);
      if (!rows[0]) throw notFound('Post not found');
      if (rows[0].author_id !== req.userId) throw forbidden('Only the author can grant access');
      await assertAudience(db, req.userId, Object.keys(env));
      await insertEnvelopes(db, id, env);
    });
    res.status(204).end();
  });

  r.delete('/:id', async (req, res) => {
    const { rowCount } = await pool.query('DELETE FROM posts WHERE id=$1 AND author_id=$2', [
      parse(S.uuid, req.params.id),
      req.userId,
    ]);
    if (!rowCount) throw notFound('Post not found');
    res.status(204).end();
  });

  return r;
}
