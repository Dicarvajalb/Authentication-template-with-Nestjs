import { JSONSchemaType } from 'ajv';

export interface RegisterDto {
  email: string;
  username: string;
  password: string;
}
export function buildRegisterSchema(
  errorMessage: string,
  passwordRegex: string,
): JSONSchemaType<RegisterDto> {
  // Build the password pattern dynamically from policy flags

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
        pattern: passwordRegex,
        errorMessage: errorMessage,
      },
    },
    required: ['email', 'username', 'password'],
    additionalProperties: false, // strips unknown fields
  };
}
