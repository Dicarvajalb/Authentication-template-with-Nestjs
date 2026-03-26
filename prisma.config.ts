import { defineConfig } from 'prisma/config';
import { loadEnvFiles } from './src/config/env.utils';

loadEnvFiles();

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: process.env['DATABASE_URL'],
  },
});
