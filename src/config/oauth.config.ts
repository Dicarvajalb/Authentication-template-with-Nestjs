import { registerAs } from '@nestjs/config';
import { getRequiredString } from './env.utils';

export default registerAs('oauth', () => ({
  googleClientId: getRequiredString(process.env, 'GOOGLE_CLIENT_ID'),
  googleClientSecret: getRequiredString(process.env, 'GOOGLE_CLIENT_SECRET'),
  googleCallbackUrl: getRequiredString(process.env, 'GOOGLE_CALLBACK_URL'),
}));
