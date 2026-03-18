import { JSONSchemaType } from 'ajv';

export interface ChangePasswordDTO {
  currentPassword: string;
  newPassword: string;
}
export function buildChangePasswordSchema(
  errorMessage: string,
  passwordRegex: string,
): JSONSchemaType<ChangePasswordDTO> {
  return {
    type: 'object',
    properties: {
      currentPassword: {
        type: 'string',
        pattern: passwordRegex,
        errorMessage: 'Invalid currentPassword. ' + errorMessage,
      },
      newPassword: {
        type: 'string',
        pattern: passwordRegex,
        errorMessage: 'Invalid newPassword. ' + errorMessage,
      },
    },
    required: ['currentPassword', 'newPassword'],
    additionalProperties: false,
  };
}
