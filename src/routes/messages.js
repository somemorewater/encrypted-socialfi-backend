import { Router } from 'express';
import { z } from 'zod';
import { verifyParts } from '../crypto/zk.js';
import { badRequest, notFound, parse } from '../errors.js';
import * as S from '../schemas.js';

const sendBody = z.object({
  id: S.uuid,
  recipientId: S.uuid,
  ciphertext: S.ciphertext,
  signature: S.signature,
  keyForSender: S.wrappedKey,
  keyForRecipient: S.wrappedKey,
});
const listQuery = S.cursor.extend({ with: S.handle.optional() });

export function messageRoutes({ pool }) {
  const r = Router();

  r.post('/', async (req, res) => {
    const b = parse(sendBody, req.body);
    if (b.recipientId === req.userId) throw badRequest('Cannot message yourself');
    const { rows: u } = await pool.query('SELECT identity_pubkey FROM users WHERE id=$1', [req.userId]);
    if (!verifyParts(u[0].identity_pubkey, b.signature, ['msg', b.id, b.recipientId, b.ciphertext])) {
      throw badRequest('Invalid signature', 'bad_signature');
    }
    const { rowCount } = await pool.query('SELECT 1 FROM users WHERE id=$1', [b.recipientId]);
    if (!rowCount) throw notFound('Recipient not found');
    const { rows } = await pool.query(
      `INSERT INTO messages (id, sender_id, recipient_id, ciphertext, signature, key_for_sender, key_for_recipient)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING seq, created_at`,
      [b.id, req.userId, b.recipientId, b.ciphertext, b.signature, b.keyForSender, b.keyForRecipient],
    );
    res.status(201).json({ id: b.id, seq: Number(rows[0].seq), createdAt: rows[0].created_at });
  });

  /** Messages I sent or received, optionally filtered to one conversation partner. Returns my wrapped key only. */
  r.get('/', async (req, res) => {
    const q = parse(listQuery, req.query);
    const { rows } = await pool.query(
      `SELECT m.id, m.seq, m.ciphertext, m.signature, m.created_at,
              m.sender_id, s.handle AS sender_handle, s.identity_pubkey AS sender_identity_pubkey,
              m.recipient_id, rc.handle AS recipient_handle,
              CASE WHEN m.sender_id = $1 THEN m.key_for_sender ELSE m.key_for_recipient END AS wrapped_key
       FROM messages m
       JOIN users s  ON s.id  = m.sender_id
       JOIN users rc ON rc.id = m.recipient_id
       WHERE (m.sender_id = $1 OR m.recipient_id = $1)
         AND ($2::text IS NULL OR s.handle = $2 OR rc.handle = $2)
         AND ($3::bigint IS NULL OR m.seq < $3)
       ORDER BY m.seq DESC LIMIT $4`,
      [req.userId, q.with ?? null, q.before ?? null, q.limit],
    );
    const messages = rows.map((m) => ({
      id: m.id,
      seq: Number(m.seq),
      sender: { id: m.sender_id, handle: m.sender_handle, identityPubkey: m.sender_identity_pubkey },
      recipient: { id: m.recipient_id, handle: m.recipient_handle },
      ciphertext: m.ciphertext,
      signature: m.signature,
      wrappedKey: m.wrapped_key,
      createdAt: m.created_at,
    }));
    res.json({ messages, nextBefore: messages.length === q.limit ? messages[messages.length - 1].seq : null });
  });

  return r;
}
