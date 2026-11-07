import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { requireAuth } from './middleware/auth.js';
import { errorHandler, notFound } from './errors.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes } from './routes/users.js';
import { postRoutes } from './routes/posts.js';
import { messageRoutes } from './routes/messages.js';
import { walletRoutes } from './routes/wallet.js';

export function createApp({ pool, config }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '256kb' }));

  // NOTE: in-memory limiter => per-replica limits. Use a shared store (e.g. Redis) when scaling out in production.
  const limiter = (max) => rateLimit({ windowMs: 60_000, limit: max, standardHeaders: 'draft-7', legacyHeaders: false });
  app.use(limiter(config.rateLimitPerMin));

  app.get('/healthz', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'ok' });
    } catch {
      res.status(503).json({ status: 'db_unavailable' });
    }
  });

  const auth = requireAuth(config);
  const deps = { pool, config };
  app.use('/v1/auth', limiter(config.authRateLimitPerMin), authRoutes(deps));
  app.use('/v1/users', auth, userRoutes(deps));
  app.use('/v1/posts', auth, postRoutes(deps));
  app.use('/v1/messages', auth, messageRoutes(deps));
  app.use('/v1/wallet', auth, walletRoutes(deps));

  app.use((_req, _res, next) => next(notFound('Route not found')));
  app.use(errorHandler);
  return app;
}
