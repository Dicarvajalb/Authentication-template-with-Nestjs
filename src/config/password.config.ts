import { registerAs } from '@nestjs/config';
import { getRequiredString } from './env.utils';

export default registerAs('password', () => ({
  regex: getRequiredString(process.env, 'PASSWORD_REGEX'),
  errorMessage: getRequiredString(process.env, 'PASSWORD_ERROR_MESSAGE'),
}));
