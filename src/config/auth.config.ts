import { registerAs } from '@nestjs/config';
import { getNumber, getRequiredString } from './env.utils';

export default registerAs('auth', () => ({
  jwtSecret: getRequiredString(process.env, 'JWT_SECRET'),
  jwtDurationMs: getNumber(process.env, 'JWT_DURATION'),
  jwtRefreshDurationMs: getNumber(process.env, 'JWT_REFRESH_DURATION'),
  jwtPurgeCron: process.env.JWT_PURGE_CRON?.trim() || '0 0 * * *',
  lockoutMaxAttempts: getNumber(process.env, 'LOCKOUT_MAX_ATTEMPTS', 5),
  lockoutDurationMinutes: getNumber(
    process.env,
    'LOCKOUT_DURATION_MINUTES',
    15,
  ),
}));
