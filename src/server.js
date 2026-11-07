import { loadConfig } from './config.js';
import { createPool } from './db.js';
import { migrate } from './migrate.js';
import { createApp } from './app.js';

const config = loadConfig();
const pool = createPool(config.databaseUrl);

await migrate(pool);
const app = createApp({ pool, config });
const server = app.listen(config.port, () => console.log(`socialfi api listening on :${config.port} (${config.nodeEnv})`));

// Housekeeping: expired ZK challenges are useless; any replica may prune them.
const prune = setInterval(() => {
  pool.query('DELETE FROM auth_challenges WHERE expires_at < now() - interval \'1 minute\'').catch(() => {});
}, 60_000);
prune.unref();

// Graceful shutdown (rolling deploys / container stop).
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`${sig} received, draining...`);
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}
