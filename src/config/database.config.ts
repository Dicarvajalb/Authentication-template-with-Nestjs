import { registerAs } from '@nestjs/config';
import { getRequiredString } from './env.utils';

export default registerAs('database', () => ({
  url: getRequiredString(process.env, 'DATABASE_URL'),
}));
