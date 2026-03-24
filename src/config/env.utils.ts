const DEFAULT_NODE_ENV = 'development';

export function getNodeEnv(): string {
  return process.env.NODE_ENV?.trim() || DEFAULT_NODE_ENV;
}

export function getEnvFilePaths(nodeEnv = getNodeEnv()): string[] {
  return [`.env.${nodeEnv}.local`, `.env.${nodeEnv}`, '.env.local', '.env'];
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
