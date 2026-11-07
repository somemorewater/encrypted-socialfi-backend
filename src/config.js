export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const isProd = nodeEnv === 'production';
  const jwtSecret = env.JWT_SECRET;
  if (isProd && (!jwtSecret || jwtSecret.length < 32)) {
    throw new Error('JWT_SECRET must be set (>= 32 chars) in production');
  }
  return {
    nodeEnv,
    isProd,
    port: Number(env.PORT ?? 3000),
    databaseUrl: env.DATABASE_URL ?? 'postgres://socialfi:socialfi@localhost:5432/socialfi',
    jwtSecret: jwtSecret ?? 'dev-only-insecure-secret-change-me-0000000000',
    jwtTtlSeconds: Number(env.JWT_TTL_SECONDS ?? 3600),
    challengeTtlSeconds: Number(env.CHALLENGE_TTL_SECONDS ?? 120),
    maxAudience: Number(env.MAX_AUDIENCE ?? 500),
    faucetEnabled: (env.ENABLE_FAUCET ?? (isProd ? 'false' : 'true')) === 'true',
    faucetAmount: Number(env.FAUCET_AMOUNT ?? 1000),
    trustProxy: env.TRUST_PROXY ? Number(env.TRUST_PROXY) : 0,
    rateLimitPerMin: Number(env.RATE_LIMIT_PER_MIN ?? 300),
    authRateLimitPerMin: Number(env.AUTH_RATE_LIMIT_PER_MIN ?? 30),
  };
}
