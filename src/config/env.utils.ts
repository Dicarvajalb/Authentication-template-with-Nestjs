import { existsSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { config as loadEnv } from 'dotenv';

const DEFAULT_NODE_ENV = 'development';

export function getNodeEnv(): string {
  return process.env.NODE_ENV?.trim() || DEFAULT_NODE_ENV;
}

export function getEnvFilePaths(nodeEnv = getNodeEnv()): string[] {
  return [`.env.${nodeEnv}.local`, `.env.${nodeEnv}`, '.env.local', '.env'];
}

export function loadEnvFiles(nodeEnv = getNodeEnv()): void {
  for (const envFile of getEnvFilePaths(nodeEnv)) {
    const envPath = resolve(process.cwd(), envFile);
    if (existsSync(envPath)) {
      loadEnv({ path: envPath, override: false });
    }
  }
}

export function getRequiredFileContents(path: string): string {
  const resolvedPath = resolve(process.cwd(), path);

  if (!existsSync(resolvedPath)) {
    throw new Error(`Required file ${resolvedPath} was not found`);
  }

  return readFileSync(resolvedPath, 'utf8');
}

export function getRequiredString(
  env: NodeJS.ProcessEnv,
  key: string,
): string {
  const value = env[key]?.trim();
  if (!value) {
    throw new Error(`Environment variable ${key} is required`);
  }

  return value;
}

export function getNumber(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback?: number,
): number {
  const rawValue = env[key];

  if (rawValue === undefined || rawValue === null || rawValue === '') {
    if (fallback !== undefined) {
      return fallback;
    }

    throw new Error(`Environment variable ${key} is required`);
  }

  const value = Number(rawValue);
  if (Number.isNaN(value)) {
    throw new Error(`Environment variable ${key} must be a valid number`);
  }

  return value;
}
