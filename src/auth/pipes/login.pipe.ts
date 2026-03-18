import { Injectable } from '@nestjs/common';
import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import { buildLoginSchema, LoginDto } from '../dto/login.dto';

@Injectable()
export class LoginValidationPipe extends AjvValidationPipe<LoginDto> {
  constructor() {
    super(buildLoginSchema());
  }
}
