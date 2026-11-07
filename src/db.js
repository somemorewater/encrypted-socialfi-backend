import pg from 'pg';

export function createPool(connectionString) {
  return new pg.Pool({ connectionString, max: Number(process.env.PG_POOL_MAX ?? 10) });
}

/** Run `fn(client)` inside a transaction. Rolls back on any error. */
export async function tx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
