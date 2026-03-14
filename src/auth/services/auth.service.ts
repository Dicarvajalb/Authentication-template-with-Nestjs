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
import { AuthTokens, TokenPayload } from '../interfaces/auth.entities';
import { AUTH_DB, type AuthDBI, type AuthServiceI } from '../interfaces/auth.utilities';
import { AuthPasswordService } from './auth-password.service';
import { AuthTokenService } from './auth-token.service';

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

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
    };

    return {
      token: this.tokenService.signAccess(payload),
      expiresIn:
        this.configService.get<number>('JWT_DURATION') ?? 36000,
    };
  }

  public async register(
    username: string,
    password: string,
    email: string,
  ): Promise<{ user: UserEntity; tokens: AuthTokens }> {
    try {
      const existing = await this.userService.findByUsernameOrEmail(username, email);

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
        expiresIn: this.configService.get<number>('JWT_DURATION')  || 36000,
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
  public async changePassword(token: string , current: string, next: string): Promise<UserEntity> {
    const isValid = this.tokenService.verifyAccess("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OWQ1ZTllYi0zNzg5LTQxNmEtODc4Ni0xYzVjZWZjYzE3YTMiLCJlbWFpbCI6ImRpZUBob2xhMS5jb20iLCJpYXQiOjE3NzM0NjMwNjksImV4cCI6MTc3MzQ2MzEwNX0.enlossdFx73Okxbgc2gsWk3UOlmGJ6ZaLj-FMR9KwJA");
    console.log("Valid", isValid)
    if (!isValid) {
      throw new UnauthorizedException('Invalid token');
    }
    const user = await this.userService.findById(isValid.sub);
    if (!user) {
      throw new UnauthorizedException('User could not be found');
    }
    if (!(await this.passwordService.verify(current, next ))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const newUser = await this.userService.updateUser(user.username, user.email, await this.passwordService.hash(next));
    return newUser;
  }
}
