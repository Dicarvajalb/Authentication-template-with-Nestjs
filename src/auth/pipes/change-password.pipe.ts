import { Inject, Injectable } from '@nestjs/common';
import type { ConfigType } from '@nestjs/config';
import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import passwordConfig from 'src/config/password.config';
import { buildChangePasswordSchema, ChangePasswordDTO } from '../dto/change-password.dto';

@Injectable()
export class ChangePassValidationPipe extends AjvValidationPipe<ChangePasswordDTO> {
  constructor(
    @Inject(passwordConfig.KEY)
    configuration: ConfigType<typeof passwordConfig>,
  ) {
    super(
      buildChangePasswordSchema(
        configuration.errorMessage,
        configuration.regex,
      ),
    );
  }
}
