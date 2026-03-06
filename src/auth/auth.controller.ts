import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
} from '@nestjs/common';

import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import { AuthService } from './auth.service';
import type { RegisterDto } from './dto/register.dto';
import { AuthDTO } from './dto/sign.dto';

@Controller('auth')
export class AuthController {
  private readonly registerPipe: AjvValidationPipe<RegisterDto>;

  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() data: RegisterDto): Promise<AuthDTO> {
    try {
      const serviceRes = await this.authService.register(
        data.username,
        data.password,
        data.email,
      );
      console.log('⚙️ ~ AuthController ~ register ~ token:', serviceRes.jwt);

      return { access_token: serviceRes.jwt };
    } catch (error) {
      throw new HttpException(error, HttpStatus.BAD_REQUEST);
    }
  }
  @Post('signin')
  async signIn(@Body() data: RegisterDto): Promise<AuthDTO> {
    try {
      const token = await this.authService.signIn(data.username, data.password);

      return { access_token: token.jwt };
    } catch (error) {
      throw new HttpException(error, HttpStatus.BAD_REQUEST);
    }
  }
}
