import type { JSONSchemaType } from 'ajv';

export interface LoginDto {
  email: string;
  password: string;
}

export function buildLoginSchema(): JSONSchemaType<LoginDto> {
  return {
    type: 'object',
    properties: {
      email: {
        type: 'string',
        format: 'email',
        errorMessage: 'Must be a valid email address',
      },
      password: {
        type: 'string',
        minLength: 1,
        errorMessage: 'Password is required',
      },
    },
    required: ['email', 'password'],
    additionalProperties: false,
  };
}
