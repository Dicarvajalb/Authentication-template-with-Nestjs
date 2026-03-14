import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import { buildChangePasswordSchema, ChangePasswordDTO } from '../dto/change-password.dto';

@Injectable()
export class ChangePassValidationPipe extends AjvValidationPipe<ChangePasswordDTO> {
  constructor(config: ConfigService) {
    const errorMessage = config.get<string>('PASSWORD_ERROR_MESSAGE') || '';
    const passwordRegex = config.get<string>('PASSWORD_REGEX') || '';
    super(buildChangePasswordSchema(errorMessage, passwordRegex));
  }
}
