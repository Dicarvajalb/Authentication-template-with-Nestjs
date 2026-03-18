import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Query,
  Patch,
  Post,
  Req,
  Res,
  UseGuards,
  UsePipes,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';

import type { LoginDto } from './dto/login.dto';
import type { RegisterDto } from './dto/register.dto';
import { AuthDTO } from './dto/sign.dto';
import { LoginValidationPipe } from './pipes/login.pipe';
import { RegisterValidationPipe } from './pipes/register.pipe';
import { AuthService } from './services/auth.service';
import { ChangePassValidationPipe } from './pipes/change-password.pipe';
import type { ChangePasswordDTO } from './dto/change-password.dto';
import { JwtBearerGuard } from './guards/jwt-bearer.guard';
import type { TokenPayload } from './interfaces/auth.entities';
import { OAuthGoogleService } from './services/oauth.service';
import { AuthTokenService } from './services/auth-token.service';

const ACCESS_TOKEN_COOKIE = 'access_token';

type RequestWithUser = Request & { user: TokenPayload };

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly OAuthGoogleService: OAuthGoogleService,
    private readonly tokenService: AuthTokenService,
  ) {}

  private setAccessTokenCookie(
    res: Response,
    token: string,
    expiresInSeconds: number,
  ): void {
    const secure = this.configService.get<string>('NODE_ENV') === 'production';
    res.cookie(ACCESS_TOKEN_COOKIE, token, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      path: '/',
      maxAge: expiresInSeconds * 1000,
    });
  }

  private clearAccessTokenCookie(res: Response): void {
    const secure = this.configService.get<string>('NODE_ENV') === 'production';
    res.clearCookie(ACCESS_TOKEN_COOKIE, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      path: '/',
    });
  }

  @Post('register')
  @UsePipes(RegisterValidationPipe)
  async register(
    @Body() data: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthDTO> {
    const serviceRes = await this.authService.register(
      data.username,
      data.password,
      data.email,
    );
    this.setAccessTokenCookie(
      res,
      serviceRes.tokens.token,
      serviceRes.tokens.expiresIn,
    );
    return { access_token: serviceRes.tokens.token };
  }

  @Post('login')
  @UsePipes(LoginValidationPipe)
  async signIn(
    @Body() data: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthDTO> {
    const tokens = await this.authService.login(data.email, data.password);
    this.setAccessTokenCookie(res, tokens.token, tokens.expiresIn);
    return { access_token: tokens.token };
  }

  @Post('logout')
  @UseGuards(JwtBearerGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.authService.logout(req.user.sub);
    this.clearAccessTokenCookie(res);
  }

  @Patch('change-password')
  @UseGuards(JwtBearerGuard)
  @UsePipes(ChangePassValidationPipe)
  @HttpCode(HttpStatus.NO_CONTENT)
  async changePassword(
    @Req() req: RequestWithUser,
    @Body() data: ChangePasswordDTO,
  ): Promise<void> {
    await this.authService.changePassword(
      req.user.sub,
      data.currentPassword,
      data.newPassword,
    );
  }

  @Get('google')
  async googleAuth(@Res() res: Response): Promise<void> {
    const { url } = await this.OAuthGoogleService.createAuthRedirectUrl();
    res.redirect(url);
  }

  @Post('google/link')
  @UseGuards(JwtBearerGuard)
  async googleLink(): Promise<{ url: string }> {
    // The user must be authenticated (JWT). Linking is completed on callback,
    // where the existing auth cookie (if present) is used to decide link vs create.
    return await this.OAuthGoogleService.createAuthRedirectUrl();
  }

  @Get('google/callback')
  async googleCallback(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
  ): Promise<AuthDTO> {
    if (!code || !state) {
      throw new UnauthorizedException('Missing code or state');
    }

    // Optional linking: if user already authenticated via cookie, link instead of creating a new user.
    let linkingUserId: string | undefined;
    const accessToken = (req as any).cookies?.access_token as
      | string
      | undefined;
    if (accessToken) {
      try {
        const payload = this.tokenService.verifyAccess(
          accessToken,
        ) as TokenPayload;
        linkingUserId = payload.sub;
      } catch {
        linkingUserId = undefined;
      }
    }

    const tokens = await this.OAuthGoogleService.handleCallback({
      code,
      state,
      linkingUserId,
    });

    this.setAccessTokenCookie(res, tokens.token, tokens.expiresIn);
    return { access_token: tokens.token };
  }
}
