import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import { buildRegisterSchema, RegisterDto } from '../dto/register.dto';

@Injectable()
export class RegisterValidationPipe extends AjvValidationPipe<RegisterDto> {
  constructor(config: ConfigService) {
    const errorMessage = config.get<string>('PASSWORD_ERROR_MESSAGE') || '';
    const passwordRegex = config.get<string>('PASSWORD_REGEX') || '';
    super(buildRegisterSchema(errorMessage, passwordRegex));
  }
}
