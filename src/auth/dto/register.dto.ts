import { JSONSchemaType } from 'ajv';

export interface RegisterDto {
  email: string;
  username: string;
  password: string;
}
export function buildRegisterSchema(policy: {
  minLength: number;
  requireUppercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
}): JSONSchemaType<RegisterDto> {
  // Build the password pattern dynamically from policy flags
  const lookaheads: string[] = [];
  if (policy.requireUppercase) lookaheads.push('(?=.*[A-Z])');
  if (policy.requireNumbers) lookaheads.push('(?=.*[0-9])');
  if (policy.requireSymbols) lookaheads.push('(?=.*[^A-Za-z0-9])');

  const passwordPattern =
    lookaheads.length > 0
      ? `^${lookaheads.join('')}.{${policy.minLength},}$`
      : `^.{${policy.minLength},}$`;

  return {
    type: 'object',
    properties: {
      email: {
        type: 'string',
        format: 'email',
        errorMessage: 'Must be a valid email address',
      },
      username: {
        type: 'string',
        minLength: 3,
        maxLength: 30,
        pattern: '^[a-zA-Z0-9_]+$',
        errorMessage: 'Username must be 3–30 alphanumeric characters',
      },
      password: {
        type: 'string',
        minLength: policy.minLength,
        pattern: passwordPattern,
        errorMessage:
          `Password must be at least ${policy.minLength} characters` +
          `${policy.requireUppercase ? ', contain an uppercase letter' : ''}` +
          `${policy.requireNumbers ? ', a number' : ''}` +
          `${policy.requireSymbols ? ', a symbol' : ''}`,
      },
    },
    required: ['email', 'username', 'password'],
    additionalProperties: false, // strips unknown fields
  };
}
