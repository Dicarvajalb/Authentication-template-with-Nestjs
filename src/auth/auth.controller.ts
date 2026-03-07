import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
  UsePipes,
} from '@nestjs/common';

import { AjvValidationPipe } from 'src/common/pipes/ajv.pipes';
import { AuthService } from './auth.service';
import type { RegisterDto } from './dto/register.dto';
import { AuthDTO } from './dto/sign.dto';
import { RegisterValidationPipe } from './pipes/register.pipe';

@Controller('auth')
export class AuthController {
  private readonly registerPipe: AjvValidationPipe<RegisterDto>;

  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UsePipes(RegisterValidationPipe)
  async register(@Body() data: RegisterDto): Promise<AuthDTO> {
    const serviceRes = await this.authService.register(
      data.username,
      data.password,
      data.email,
    );

    return { access_token: serviceRes.jwt };
  }
  @Post('login')
  async signIn(@Body() data: RegisterDto): Promise<AuthDTO> {
    try {
      const token = await this.authService.login(data.email, data.password);

      return { access_token: token.jwt };
    } catch (error) {
      throw new HttpException(error, HttpStatus.BAD_REQUEST);
    }
  }
}
