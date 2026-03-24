import { registerAs } from '@nestjs/config';
import { getNodeEnv, getNumber } from './env.utils';

export default registerAs('app', () => {
  const nodeEnv = getNodeEnv();

  return {
    nodeEnv,
    isProduction: nodeEnv === 'production',
    port: getNumber(process.env, 'PORT', 3001),
  };
});
