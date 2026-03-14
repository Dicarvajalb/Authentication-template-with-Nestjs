import { Body, Controller, HttpCode, HttpStatus, Patch, Post, UsePipes } from '@nestjs/common';

import type { LoginDto } from './dto/login.dto';
import type { RegisterDto } from './dto/register.dto';
import { AuthDTO } from './dto/sign.dto';
import { LoginValidationPipe } from './pipes/login.pipe';
import { RegisterValidationPipe } from './pipes/register.pipe';
import { AuthService } from './services/auth.service';
import { ChangePassValidationPipe } from './pipes/change-password.pipe';
import type { ChangePasswordDTO } from './dto/change-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UsePipes(RegisterValidationPipe)
  async register(@Body() data: RegisterDto): Promise<AuthDTO> {
    const serviceRes = await this.authService.register(
      data.username,
      data.password,
      data.email,
    );

    return { access_token: serviceRes.tokens.token };
  }
  @Post('login')
  @UsePipes(LoginValidationPipe)
  async signIn(@Body() data: LoginDto): Promise<AuthDTO> {
    const tokens = await this.authService.login(data.email, data.password);
    return { access_token: tokens.token };
  }
  @Patch("change-password")
  @UsePipes(ChangePassValidationPipe)
  @HttpCode(HttpStatus.NO_CONTENT)
  async changePassword(@Body() data: ChangePasswordDTO): Promise<undefined> {
    await this.authService.changePassword(data.token, data.currentPassword, data.nextPassword);
    
  }
}
