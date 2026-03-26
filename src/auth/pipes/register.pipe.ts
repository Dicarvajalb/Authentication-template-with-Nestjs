import { Inject, Injectable } from '@nestjs/common';
import type { ConfigType } from '@nestjs/config';
import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import passwordConfig from 'src/config/password.config';
import { buildRegisterSchema, RegisterDto } from '../dto/register.dto';

@Injectable()
export class RegisterValidationPipe extends AjvValidationPipe<RegisterDto> {
  constructor(
    @Inject(passwordConfig.KEY)
    configuration: ConfigType<typeof passwordConfig>,
  ) {
    super(
      buildRegisterSchema(
        configuration.errorMessage,
        configuration.regex,
      ),
    );
  }
}
