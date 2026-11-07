import jwt from 'jsonwebtoken';
import { unauthorized } from '../errors.js';

export function issueToken(config, userId) {
  return jwt.sign({ sub: userId }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: config.jwtTtlSeconds,
    issuer: 'socialfi',
  });
}

/** Stateless bearer-token auth: any API replica can verify without shared session state. */
export function requireAuth(config) {
  return (req, _res, next) => {
    const header = req.get('authorization') ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) return next(unauthorized());
    try {
      const payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'], issuer: 'socialfi' });
      req.userId = payload.sub;
      next();
    } catch {
      next(unauthorized('Invalid or expired token'));
    }
  };
}
