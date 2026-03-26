import {
  ConflictException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import type { ConfigType } from '@nestjs/config';
import authConfig from 'src/config/auth.config';
import { UserCRUDService } from 'src/user/services/user-crud.service';
import { UserEntity } from 'src/user/interfaces/user.entities';
import {
  AuthTokens,
  JWTToken,
  TokenPayload,
  TokenType,
} from '../interfaces/auth.entities';
import {
  AUTH_DB,
  type AuthDBI,
  type AuthServiceI,
} from '../interfaces/auth.utilities';
import { AuthPasswordService } from './auth-password.service';
import { AuthTokenService } from './auth-token.service';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService implements AuthServiceI {
  constructor(
    private readonly passwordService: AuthPasswordService,
    private readonly tokenService: AuthTokenService,
    private readonly userService: UserCRUDService,
    @Inject(authConfig.KEY)
    private readonly authConfiguration: ConfigType<typeof authConfig>,
    @Inject(AUTH_DB) private readonly authDb: AuthDBI,
  ) {}

  private async issueTokenPair(userId: string): Promise<AuthTokens> {
    const accessTokenRecord: JWTToken = {
      userId,
      type: 'access',
      expiresAt: new Date(Date.now() + this.authConfiguration.jwtDurationMs),
      jti: randomUUID(),
    };
    await this.authDb.saveToken(accessTokenRecord);

    const accessTokenPayload: TokenPayload = {
      sub: accessTokenRecord.userId,
      exp: Math.floor(accessTokenRecord.expiresAt.getTime() / 1000),
      jti: accessTokenRecord.jti,
      type: 'access',
    };

    const refreshTokenRecord: JWTToken = {
      userId,
      type: 'refresh',
      expiresAt: new Date(
        Date.now() + this.authConfiguration.jwtRefreshDurationMs,
      ),
      jti: randomUUID(),
    };
    await this.authDb.saveToken(refreshTokenRecord);

    const refreshTokenPayload: TokenPayload = {
      sub: refreshTokenRecord.userId,
      exp: Math.floor(refreshTokenRecord.expiresAt.getTime() / 1000),
      jti: refreshTokenRecord.jti,
      type: 'refresh',
    };

    return {
      access_token: this.tokenService.signAccess(accessTokenPayload),
      refresh_token: this.tokenService.signRefresh(refreshTokenPayload),
    };
  }

  private buildTokenPair(userId: string): {
    accessTokenRecord: JWTToken;
    refreshTokenRecord: JWTToken;
    tokens: AuthTokens;
  } {
    const accessTokenRecord: JWTToken = {
      userId,
      type: 'access',
      expiresAt: new Date(Date.now() + this.authConfiguration.jwtDurationMs),
      jti: randomUUID(),
    };

    const accessTokenPayload: TokenPayload = {
      sub: accessTokenRecord.userId,
      exp: Math.floor(accessTokenRecord.expiresAt.getTime() / 1000),
      jti: accessTokenRecord.jti,
      type: 'access',
    };

    const refreshTokenRecord: JWTToken = {
      userId,
      type: 'refresh',
      expiresAt: new Date(
        Date.now() + this.authConfiguration.jwtRefreshDurationMs,
      ),
      jti: randomUUID(),
    };

    const refreshTokenPayload: TokenPayload = {
      sub: refreshTokenRecord.userId,
      exp: Math.floor(refreshTokenRecord.expiresAt.getTime() / 1000),
      jti: refreshTokenRecord.jti,
      type: 'refresh',
    };

    return {
      accessTokenRecord,
      refreshTokenRecord,
      tokens: {
        access_token: this.tokenService.signAccess(accessTokenPayload),
        refresh_token: this.tokenService.signRefresh(refreshTokenPayload),
      },
    };
  }

  public issueTokenPairForUser(userId: string): Promise<AuthTokens> {
    return this.issueTokenPair(userId);
  }

  public async login(email: string, password: string): Promise<AuthTokens> {
    const user = await this.userService.findByUsernameOrEmail(undefined, email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const maxAttempts = this.authConfiguration.lockoutMaxAttempts;
    const durationMinutes = this.authConfiguration.lockoutDurationMinutes;

    const attempt = await this.authDb.findLoginAttemptByUserId(user.id);

    const now = new Date();
    const lockedUntil = attempt?.lockedUntil ?? null;
    if (lockedUntil && lockedUntil > now) {
      throw new UnauthorizedException('Account temporarily locked');
    }

    const verified = await this.passwordService.verify(
      password,
      user.password || '',
    );
    if (!verified) {
      const newCount = (attempt?.failedCount ?? 0) + 1;
      const lockEnd =
        newCount >= maxAttempts
          ? new Date(now.getTime() + durationMinutes * 60 * 1000)
          : null;
      await this.authDb.upsertLoginAttempt(user.id, {
        failedCount: newCount,
        lockedUntil: lockEnd,
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.authDb.upsertLoginAttempt(user.id, {
      failedCount: 0,
      lockedUntil: null,
    });

    return this.issueTokenPair(user.id);
  }

  public async register(
    username: string,
    password: string,
    email: string,
  ): Promise<{ tokens: AuthTokens }> {
    const existing = await this.userService.findByUsernameOrEmail(
      username,
      email,
    );

    if (existing) {
      throw new ConflictException(
        'User with provided credentials already exists',
      );
    }

    const hashedPassword = await this.passwordService.hash(password);
    const userId = randomUUID();
    const { accessTokenRecord, refreshTokenRecord, tokens } =
      this.buildTokenPair(userId);

    const user = await this.authDb.createUserWithTokens({
      user: {
        id: userId,
        username,
        email,
        password: hashedPassword,
      },
      accessToken: accessTokenRecord,
      refreshToken: refreshTokenRecord,
    });

    if (!user) {
      throw new InternalServerErrorException('User could not be created');
    }

    return { tokens };
  }

  public async logout(token: string): Promise<void> {
    const decoded = this.tokenService.decodeToken(token);
    this.authDb.updateAllRevokedByUserId(decoded.sub, false);
  }

  /**
   * Changes password for the user. Re-verifies currentPassword with timingSafeEqual
   * (via AuthPasswordService.verify), then updates hash and revokes all refresh tokens (AUTH-12, AUTH-13).
   */
  public async changePassword(
    token: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    if (currentPassword === newPassword) {
      throw new UnauthorizedException('Same credentials');
    }
    const decodedToken = this.tokenService.verifyAccess(token);
    const user = await this.userService.findById(decodedToken.sub);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.password) {
      throw new UnauthorizedException(
        'Account has no password (e.g. Google-only). Cannot change password.',
      );
    }
    const currentValid = await this.passwordService.verify(
      currentPassword,
      user.password,
    );
    if (!currentValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const newHash = await this.passwordService.hash(newPassword);
    await this.userService.updateUser(user.username, user.email, newHash);
    await this.authDb.updateAllRevokedByUserId(user.id, true);
  }

  public async refresh(refreshToken: string): Promise<AuthTokens> {
    const validatedToken = this.tokenService.verifyRefresh(refreshToken);
    if (!validatedToken.jti) {
      throw new UnauthorizedException();
    }
    if (validatedToken.type !== 'refresh') {
      throw new UnauthorizedException();
    }
    const storedToken = await this.authDb.findToken(validatedToken.jti);
    if (storedToken.revoked) {
      throw new UnauthorizedException();
    }
    if (storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Unauthorized: Token expired');
    }
    if (storedToken.replacedByJti) {
      throw new UnauthorizedException('Unauthorized: Token reused');
    }

    const accessTokenRecord: JWTToken = {
      userId: storedToken.userId,
      type: 'access',
      expiresAt: new Date(Date.now() + this.authConfiguration.jwtDurationMs),
      jti: randomUUID(),
    };
    await this.authDb.saveToken(accessTokenRecord);

    const accessPayload: TokenPayload = {
      sub: accessTokenRecord.userId,
      exp: Math.floor(accessTokenRecord.expiresAt.getTime() / 1000),
      jti: accessTokenRecord.jti,
      type: 'access',
    };

    const refreshTokenRecord: JWTToken = {
      jti: randomUUID(),
      type: 'refresh',
      userId: storedToken.userId,
      expiresAt: new Date(
        Date.now() + this.authConfiguration.jwtRefreshDurationMs,
      ),
    };

    await this.authDb.revokeAndSaveTokenTransaction(
      storedToken.jti,
      refreshTokenRecord,
    );

    const refreshPayload: TokenPayload = {
      sub: refreshTokenRecord.userId,
      exp: Math.floor(refreshTokenRecord.expiresAt.getTime() / 1000),
      jti: refreshTokenRecord.jti,
      type: 'refresh',
    };

    return {
      access_token: this.tokenService.signAccess(accessPayload),
      refresh_token: this.tokenService.signRefresh(refreshPayload),
    };
  }
}
