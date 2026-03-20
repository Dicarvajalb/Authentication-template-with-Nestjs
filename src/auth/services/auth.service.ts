import {
  ConflictException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from 'src/generated/prisma/client';
import { UserCRUDService } from 'src/user/services/user-crud.service';
import { UserEntity } from 'src/user/interfaces/user.entities';
import {
  AuthTokens,
  RefreshToken,
  TokenPayload,
} from '../interfaces/auth.entities';
import {
  AUTH_DB,
  type AuthDBI,
  type AuthServiceI,
} from '../interfaces/auth.utilities';
import { AuthPasswordService } from './auth-password.service';
import { AuthTokenService } from './auth-token.service';
import { randomUUID } from 'crypto';

const DEFAULT_LOCKOUT_MAX_ATTEMPTS = 5;
const DEFAULT_LOCKOUT_DURATION_MINUTES = 15;

@Injectable()
export class AuthService implements AuthServiceI {
  constructor(
    private readonly passwordService: AuthPasswordService,
    private readonly tokenService: AuthTokenService,
    private readonly userService: UserCRUDService,
    private readonly configService: ConfigService,
    @Inject(AUTH_DB) private readonly authDb: AuthDBI,
  ) {}

  public async login(email: string, password: string): Promise<AuthTokens> {
    const user = await this.userService.findByUsernameOrEmail(undefined, email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const maxAttempts =
      this.configService.get<number>('LOCKOUT_MAX_ATTEMPTS') ??
      DEFAULT_LOCKOUT_MAX_ATTEMPTS;
    const durationMinutes =
      this.configService.get<number>('LOCKOUT_DURATION_MINUTES') ??
      DEFAULT_LOCKOUT_DURATION_MINUTES;

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

    const access_token: TokenPayload = {
      sub: user.id,
      type: 'access',
    };

    const refresh_token_internal: RefreshToken = {
      userId: user.id,
      expiresAt: new Date(
        Date.now() +
          (this.configService.get<number>('JWT_REFRESH_DURATION') || 0),
      ),
      familyId: randomUUID(),
      jti: randomUUID(),
    };
    this.authDb.saveRefreshToken(refresh_token_internal);

    const refresh_token_external: TokenPayload = {
      sub: refresh_token_internal.userId,
      exp: refresh_token_internal.expiresAt.getTime(),
      jti: refresh_token_internal.jti,
      type: 'refresh',
    };

    return {
      access_token: this.tokenService.signAccess(access_token),
      refresh_token: this.tokenService.signAccess(refresh_token_external),
    };
  }

  public async register(
    username: string,
    password: string,
    email: string,
  ): Promise<{ user: UserEntity; tokens: AuthTokens }> {
    try {
      const existing = await this.userService.findByUsernameOrEmail(
        username,
        email,
      );

      if (existing) {
        // Generic message — do NOT reveal whether the username or email matched.
        // (OWASP A07 — no user enumeration)
        throw new ConflictException(
          'User with provided credentials already exists',
        );
      }
      const hashedPassword = await this.passwordService.hash(password);
      const user = await this.userService.createUser(
        username,
        email,
        hashedPassword,
      );

      console.log('⚙️ ~ AuthService ~ register ~ user:', user);

      if (!user) {
        throw new InternalServerErrorException('User could not be created');
      }

      const payload: TokenPayload = {
        sub: user.id, // safe for BigInt
        email: user.email,
      };

      const tokens: AuthTokens = {
        token: this.tokenService.signAccess(payload),
        expiresIn: this.configService.get<number>('JWT_DURATION') || 36000,
      };

      return { user, tokens };
    } catch (error: unknown) {
      console.log('⚙️ ~ AuthService ~ register ~ error:', error);
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002' // Prisma unique constraint
      ) {
        throw new ConflictException(
          'User with provided credentials already exists',
        );
      }

      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'Unexpected error during registration',
      );
    }
  }

  public async logout(userId: string): Promise<void> {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new InternalServerErrorException('User could not be found');
    }
  }

  /**
   * Changes password for the user. Re-verifies currentPassword with timingSafeEqual
   * (via AuthPasswordService.verify), then updates hash and revokes all refresh tokens (AUTH-12, AUTH-13).
   */
  public async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userService.findById(userId);
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
    await this.authDb.deleteAllRefreshTokensForUser(userId);
  }

  public async refresh(refreshToken: string): Promise<AuthTokens> {
    const validatedToken = this.tokenService.verifyAccess(refreshToken);
    if (!validatedToken.jti) {
      throw new UnauthorizedException();
    }
    if (validatedToken.type !== 'refresh') {
      throw new UnauthorizedException();
    }
    const storedToken = await this.authDb.findRefreshToken(validatedToken.jti);
    if (storedToken.revoked) {
      throw new UnauthorizedException();
    }
    if (storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Unauthorized: Token expired');
    }
    if (storedToken.replacedByJti) {
      throw new UnauthorizedException('Unauthorized: Token reused');
    }

    const newAccessPayload: TokenPayload = {
      sub: storedToken.userId,
      type: 'access',
    };
    const newAccessToken: string = this.tokenService.signAccess(
      newAccessPayload,
      this.configService.get<number>('JWT_REFRESH_DURATION'),
    );
    const newRefreshPayload: TokenPayload = {
      sub: storedToken.userId,
      type: 'access',
      jti: randomUUID(),
    };
    const newRefreshToken: string = this.tokenService.signAccess(
      newRefreshPayload,
      this.configService.get<number>('JWT_REFRESH_DURATION'),
    );
    this.authDb.revokeAndSaveTokenTransaction(storedToken.jti, {
      jti: randomUUID(),
      userId: storedToken.userId,
      expiresAt: new Date(
        Date.now() +
          (this.configService.get<number>('JWT_REFRESH_DURATION') || 0),
      ),
    });
    return { access_token: newAccessToken, refresh_token: newRefreshToken };
  }
}
