import {
  Body,
  Controller,
  Get,
  Inject,
  HttpCode,
  HttpStatus,
  Query,
  Patch,
  Post,
  Req,
  Res,
  UsePipes,
  UnauthorizedException,
} from '@nestjs/common';
import type { ConfigType } from '@nestjs/config';
import type { Request, Response } from 'express';

import type { LoginDto } from './dto/login.dto';
import type { RegisterDto } from './dto/register.dto';
import type { RegisterResponseDTO } from './dto/register.res.dto';
import { LoginValidationPipe } from './pipes/login.pipe';
import { RegisterValidationPipe } from './pipes/register.pipe';
import { AuthService } from './services/auth.service';
import { ChangePassValidationPipe } from './pipes/change-password.pipe';
import type { ChangePasswordDTO } from './dto/change-password.dto';
import type { TokenPayload } from './interfaces/auth.entities';
import {
  OAUTH_SERVICE,
  type OAuthServiceI,
} from './interfaces/oauth.utilities';
import { AuthTokenService } from './services/auth-token.service';
import { Public } from 'src/common/decorators/public';
import appConfig from 'src/config/app.config';
import authConfig from 'src/config/auth.config';
import { Cookie } from 'src/common/decorators/cookies';
import { RefreshDto } from './dto/refresh.dto';
import { LoginResponseDTO } from './dto/login.res.dto';

const ACCESS_TOKEN_COOKIE = 'access_token';
const REFRESH_TOKEN_COOKIE = 'refresh_token';

type RequestWithUser = Request & { user: TokenPayload };

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @Inject(OAUTH_SERVICE)
    private readonly oauthService: OAuthServiceI,
    private readonly tokenService: AuthTokenService,
    @Inject(appConfig.KEY)
    private readonly appConfiguration: ConfigType<typeof appConfig>,
    @Inject(authConfig.KEY)
    private readonly authConfiguration: ConfigType<typeof authConfig>,
  ) {}

  private setAccessTokenCookie(
    res: Response,
    token: string,
    expiresInSeconds: number,
  ): void {
    res.cookie(ACCESS_TOKEN_COOKIE, token, {
      httpOnly: true,
      secure: this.appConfiguration.isProduction,
      sameSite: 'strict',
      path: '/',
      maxAge: expiresInSeconds * 1000,
    });
  }

  private setRefreshTokenCookie(
    res: Response,
    token: string,
    expiresInMilliseconds: number,
  ): void {
    res.cookie(REFRESH_TOKEN_COOKIE, token, {
      httpOnly: true,
      secure: this.appConfiguration.isProduction,
      sameSite: 'strict',
      path: '/auth/refresh',
      maxAge: expiresInMilliseconds,
    });
  }

  private clearAccessTokenCookie(res: Response): void {
    res.clearCookie(ACCESS_TOKEN_COOKIE, {
      httpOnly: true,
      secure: this.appConfiguration.isProduction,
      sameSite: 'strict',
      path: '/',
    });
  }

  private clearRefreshTokenCookie(res: Response): void {
    res.clearCookie(REFRESH_TOKEN_COOKIE, {
      httpOnly: true,
      secure: this.appConfiguration.isProduction,
      sameSite: 'strict',
      path: '/auth/refresh',
    });
  }

  @Post('register')
  @Public()
  @UsePipes(RegisterValidationPipe)
  async register(
    @Body() data: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RegisterResponseDTO> {
    const serviceRes = await this.authService.register(
      data.username,
      data.password,
      data.email,
    );
    this.setAccessTokenCookie(
      res,
      serviceRes.tokens.access_token,
      this.authConfiguration.jwtDurationMs,
    );
    this.setRefreshTokenCookie(
      res,
      serviceRes.tokens.refresh_token,
      this.authConfiguration.jwtRefreshDurationMs,
    );
    return {
      access_token: serviceRes.tokens.access_token,
      refresh_token: serviceRes.tokens.refresh_token,
    };
  }

  @Post('login')
  @Public()
  @UsePipes(LoginValidationPipe)
  async signIn(
    @Body() data: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDTO> {
    const tokens = await this.authService.login(data.email, data.password);
    this.setAccessTokenCookie(
      res,
      tokens.access_token,
      this.authConfiguration.jwtDurationMs,
    );
    this.setRefreshTokenCookie(
      res,
      tokens.refresh_token,
      this.authConfiguration.jwtRefreshDurationMs,
    );
    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.authService.logout(req.user.sub);
    this.clearAccessTokenCookie(res);
    this.clearRefreshTokenCookie(res);
  }

  @Patch('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  async changePassword(
    @Cookie(ACCESS_TOKEN_COOKIE) a_token: string,
    @Res({ passthrough: true }) res: Response,
    @Body(ChangePassValidationPipe) data: ChangePasswordDTO,
  ): Promise<void> {
    await this.authService.changePassword(
      a_token,
      data.currentPassword,
      data.newPassword,
    );
    this.clearAccessTokenCookie(res);
    this.clearRefreshTokenCookie(res);
  }

  @Get('google')
  @Public()
  async googleAuth(@Res() res: Response): Promise<void> {
    const { url } = await this.oauthService.createAuthRedirectUrl();
    res.redirect(url);
  }

  @Public()
  @Get('google/callback')
  async googleCallback(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
  ): Promise<LoginResponseDTO> {
    if (!code || !state) {
      throw new UnauthorizedException('Missing code or state');
    }

    const tokens = await this.oauthService.handleCallback({
      code,
      state,
    });

    this.setAccessTokenCookie(
      res,
      tokens.access_token,
      this.authConfiguration.jwtDurationMs,
    );
    this.setRefreshTokenCookie(
      res,
      tokens.refresh_token,
      this.authConfiguration.jwtRefreshDurationMs,
    );
    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    };
  }

  @Public()
  @Post('refresh')
  async refreshToken(
    @Res({ passthrough: true }) res: Response,
    @Cookie(REFRESH_TOKEN_COOKIE) refreshToken: string,
  ): Promise<RefreshDto> {
    const tokens = await this.authService.refresh(refreshToken);
    this.setAccessTokenCookie(
      res,
      tokens.access_token,
      this.authConfiguration.jwtDurationMs,
    );
    this.setRefreshTokenCookie(
      res,
      tokens.refresh_token,
      this.authConfiguration.jwtRefreshDurationMs,
    );
    return tokens;
  }
}
