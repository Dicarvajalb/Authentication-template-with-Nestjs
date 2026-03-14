import { JSONSchemaType } from 'ajv';

export interface ChangePasswordDTO {
  token: string;
  currentPassword: string;
  nextPassword: string;
}
export function buildChangePasswordSchema(
  errorMessage: string,
  passwordRegex: string,
): JSONSchemaType<ChangePasswordDTO> {
  // Build the password pattern dynamically from policy flags

  return {
    type: 'object',
    properties: {
      token:{
        type: 'string',
        errorMessage: "Token is required"
      },
      currentPassword: {
        type: 'string',
        pattern: passwordRegex,
        errorMessage: "Invalid currentPassword." + " " + errorMessage,
      },
      nextPassword: {
        type: 'string',
        pattern: passwordRegex,
        errorMessage: "Invalid nextPassword." + " " + errorMessage,
      },
    },
    required: ['currentPassword', 'nextPassword', 'token'],
    additionalProperties: false, // strips unknown fields
  };
}
