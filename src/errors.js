import { ZodError } from 'zod';

export class AppError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
export const badRequest = (m, c = 'bad_request') => new AppError(400, c, m);
export const unauthorized = (m = 'Authentication required') => new AppError(401, 'unauthorized', m);
export const forbidden = (m = 'Forbidden') => new AppError(403, 'forbidden', m);
export const notFound = (m = 'Not found') => new AppError(404, 'not_found', m);
export const conflict = (m, c = 'conflict') => new AppError(409, c, m);

export function parse(schema, data) {
  return schema.parse(data); // ZodError is mapped to 400 by the error handler
}

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, _next) {
  if (err instanceof AppError) {
    return res.status(err.status).json({ error: { code: err.code, message: err.message } });
  }
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: {
        code: 'validation_error',
        message: 'Invalid request',
        details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      },
    });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: { code: 'payload_too_large', message: 'Request body too large' } });
  }
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'bad_json', message: 'Malformed JSON' } });
  }
  if (err?.code === '23505') {
    return res.status(409).json({ error: { code: 'conflict', message: 'Resource already exists' } });
  }
  console.error(err);
  return res.status(500).json({ error: { code: 'internal', message: 'Internal server error' } });
}
