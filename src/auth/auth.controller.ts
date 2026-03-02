import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { credentialsDTO } from './dto/register.dto';
import { AuthDTO } from './dto/sign.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() data: credentialsDTO): Promise<AuthDTO> {
    try {
      const token = await this.authService.signUp(data.username, data.password);
      console.log('⚙️ ~ AuthController ~ signUp ~ token:', token);

      return token;
    } catch (error) {
      throw new HttpException(error, HttpStatus.BAD_REQUEST);
    }
  }
  @Post('signin')
  async signIn(@Body() data: credentialsDTO): Promise<AuthDTO> {
    try {
      const token = await this.authService.signIn(data.username, data.password);

      return token;
    } catch (error) {
      throw new HttpException(error, HttpStatus.BAD_REQUEST);
    }
  }
}
