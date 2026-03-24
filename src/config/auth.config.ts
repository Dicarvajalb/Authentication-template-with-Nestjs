import { registerAs } from '@nestjs/config';
import { getNumber, getRequiredString } from './env.utils';

export default registerAs('auth', () => ({
  jwtSecret: getRequiredString(process.env, 'JWT_SECRET'),
  jwtDurationMs: getNumber(process.env, 'JWT_DURATION'),
  jwtRefreshDurationMs: getNumber(process.env, 'JWT_REFRESH_DURATION'),
  lockoutMaxAttempts: getNumber(process.env, 'LOCKOUT_MAX_ATTEMPTS', 5),
  lockoutDurationMinutes: getNumber(
    process.env,
    'LOCKOUT_DURATION_MINUTES',
    15,
  ),
}));
