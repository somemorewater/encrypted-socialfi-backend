import { Router } from 'express';
import { z } from 'zod';
import { tx } from '../db.js';
import { AppError, badRequest, forbidden, notFound, parse } from '../errors.js';
import * as S from '../schemas.js';

const MAX_TIP = 1_000_000;
const tipBody = z
  .object({
    amount: z.number().int().min(1).max(MAX_TIP),
    idempotencyKey: z.string().min(8).max(100),
    postId: S.uuid.optional(),
    toHandle: S.handle.optional(),
  })
  .refine((b) => Boolean(b.postId) !== Boolean(b.toHandle), 'Provide exactly one of postId or toHandle');

const tipDto = (t) => ({
  id: t.id,
  from: t.from_user,
  to: t.to_user,
  postId: t.post_id,
  amount: Number(t.amount),
  createdAt: t.created_at,
});

export function walletRoutes({ pool, config }) {
  const r = Router();

  r.get('/', async (req, res) => {
    const [{ rows: acc }, { rows: entries }] = await Promise.all([
      pool.query('SELECT balance FROM accounts WHERE user_id=$1', [req.userId]),
      pool.query(
        'SELECT id, delta, kind, ref_id, created_at FROM ledger_entries WHERE user_id=$1 ORDER BY id DESC LIMIT 50',
        [req.userId],
      ),
    ]);
    if (!acc[0]) throw notFound('Account not found');
    res.json({
      balance: Number(acc[0].balance),
      entries: entries.map((e) => ({ id: Number(e.id), delta: Number(e.delta), kind: e.kind, refId: e.ref_id, createdAt: e.created_at })),
    });
  });

  /** Dev/test only: mint test tokens. Disabled unless ENABLE_FAUCET=true. Max once per 24h per user. */
  r.post('/faucet', async (req, res) => {
    if (!config.faucetEnabled) throw forbidden('Faucet disabled');
    const balance = await tx(pool, async (db) => {
      const { rows } = await db.query('SELECT balance FROM accounts WHERE user_id=$1 FOR UPDATE', [req.userId]);
      if (!rows[0]) throw notFound('Account not found');
      const recent = await db.query(
        `SELECT 1 FROM ledger_entries WHERE user_id=$1 AND kind='faucet' AND created_at > now() - interval '24 hours'`,
        [req.userId],
      );
      if (recent.rowCount) throw new AppError(429, 'faucet_cooldown', 'Faucet already used in the last 24h');
      await db.query('UPDATE accounts SET balance = balance + $2 WHERE user_id=$1', [req.userId, config.faucetAmount]);
      await db.query(`INSERT INTO ledger_entries (user_id, delta, kind) VALUES ($1,$2,'faucet')`, [req.userId, config.faucetAmount]);
      return Number(rows[0].balance) + config.faucetAmount;
    });
    res.json({ balance });
  });

  /**
   * Tip a creator (for a post you can read, or directly by handle).
   * Concurrency-safe across replicas: both account rows are locked in a fixed order,
   * and the idempotency key makes client retries harmless (replay returns the original tip).
   */
  r.post('/tips', async (req, res) => {
    const b = parse(tipBody, req.body);

    const { tip, replay } = await tx(pool, async (db) => {
      let toUser;
      let postId = null;
      if (b.postId) {
        // You may only tip posts you are able to read (you hold a wrapped key for it).
        const { rows } = await db.query(
          `SELECT p.id, p.author_id FROM posts p JOIN post_keys k ON k.post_id = p.id
           WHERE p.id = $1 AND k.recipient_id = $2`,
          [b.postId, req.userId],
        );
        if (!rows[0]) throw notFound('Post not found');
        toUser = rows[0].author_id;
        postId = rows[0].id;
      } else {
        const { rows } = await db.query('SELECT id FROM users WHERE handle=$1', [b.toHandle]);
        if (!rows[0]) throw notFound('User not found');
        toUser = rows[0].id;
      }
      if (toUser === req.userId) throw badRequest('You cannot tip yourself');

      // Lock both accounts in deterministic order (prevents deadlocks).
      const { rows: locked } = await db.query(
        'SELECT user_id, balance FROM accounts WHERE user_id = ANY($1::uuid[]) ORDER BY user_id FOR UPDATE',
        [[req.userId, toUser]],
      );
      const mine = locked.find((a) => a.user_id === req.userId);
      if (!mine || locked.length !== 2) throw notFound('Account not found');

      // Idempotency check happens AFTER the lock so concurrent duplicates serialize.
      const existing = await db.query('SELECT * FROM tips WHERE from_user=$1 AND idempotency_key=$2', [
        req.userId,
        b.idempotencyKey,
      ]);
      if (existing.rows[0]) {
        const t = existing.rows[0];
        if (t.to_user !== toUser || Number(t.amount) !== b.amount) {
          throw new AppError(422, 'idempotency_mismatch', 'Idempotency key reused with different parameters');
        }
        return { tip: t, replay: true };
      }

      if (Number(mine.balance) < b.amount) throw new AppError(402, 'insufficient_funds', 'Insufficient balance');

      await db.query('UPDATE accounts SET balance = balance - $2 WHERE user_id=$1', [req.userId, b.amount]);
      await db.query('UPDATE accounts SET balance = balance + $2 WHERE user_id=$1', [toUser, b.amount]);
      const { rows } = await db.query(
        `INSERT INTO tips (from_user, to_user, post_id, amount, idempotency_key)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [req.userId, toUser, postId, b.amount, b.idempotencyKey],
      );
      await db.query(
        `INSERT INTO ledger_entries (user_id, delta, kind, ref_id) VALUES ($1,$2,'tip_sent',$4), ($3,$5,'tip_received',$4)`,
        [req.userId, -b.amount, toUser, rows[0].id, b.amount],
      );
      return { tip: rows[0], replay: false };
    });

    res.status(replay ? 200 : 201).json({ ...tipDto(tip), replay });
  });

  return r;
}
