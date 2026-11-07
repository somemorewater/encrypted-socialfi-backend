import { z } from 'zod';

export const uuid = z.string().uuid();
export const handle = z.string().regex(/^[a-z0-9_]{3,24}$/, 'handle: 3-24 chars of a-z, 0-9, _');
export const hex = (bytes) => z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `expected ${bytes}-byte lowercase hex`);

export const identityPubkey = hex(33);
export const encPubkey = hex(32);
export const signature = hex(64);
export const proof = z.object({ R: hex(33), s: hex(32) });

const b64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, 'expected base64');
export const ciphertext = b64.min(40).max(100_000); // ~72 KB of plaintext
export const wrappedKey = b64.refine((s) => Buffer.from(s, 'base64').length === 92, 'wrapped key must be 92 bytes');

export const cursor = z.object({
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
});
