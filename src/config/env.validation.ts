import { getNumber, getRequiredString } from './env.utils';

export function validate(config: Record<string, unknown>): Record<string, unknown> {
  const env = config as NodeJS.ProcessEnv;

  getRequiredString(env, 'DATABASE_URL');
  getRequiredString(env, 'JWT_SECRET');
  getRequiredString(env, 'PASSWORD_REGEX');
  getRequiredString(env, 'PASSWORD_ERROR_MESSAGE');
  getRequiredString(env, 'GOOGLE_CLIENT_ID');
  getRequiredString(env, 'GOOGLE_CLIENT_SECRET');
  getRequiredString(env, 'GOOGLE_CALLBACK_URL');

  getNumber(env, 'PORT', 3001);
  getNumber(env, 'JWT_DURATION');
  getNumber(env, 'JWT_REFRESH_DURATION');
  getNumber(env, 'LOCKOUT_MAX_ATTEMPTS', 5);
  getNumber(env, 'LOCKOUT_DURATION_MINUTES', 15);

  return config;
}
