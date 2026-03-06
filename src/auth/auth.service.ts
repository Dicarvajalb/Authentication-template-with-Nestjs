import {
  ConflictException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { Prisma } from 'src/generated/prisma/client';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthService {
  private static readonly SALT_BYTES = 16; // 128-bit salt
  private static readonly KEY_LENGTH = 64; // 512-bit derived key
  private static readonly scryptAsync = promisify(scrypt);

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  private async hashPassword(plainText: string): Promise<string> {
    const salt = randomBytes(AuthService.SALT_BYTES);

    const hash = (await AuthService.scryptAsync(
      plainText,
      salt,
      AuthService.KEY_LENGTH,
    )) as Buffer;
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
  }
  private async verifyPassword(
    plainText: string,
    stored: string,
  ): Promise<boolean> {
    const [saltHex, hashHex] = stored.split(':');

    if (!saltHex || !hashHex) {
      return false; // malformed stored value — fail safely
    }

    const salt = Buffer.from(saltHex, 'hex');
    const storedHash = Buffer.from(hashHex, 'hex');
    const candidateHash = (await AuthService.scryptAsync(
      plainText,
      salt,
      AuthService.KEY_LENGTH,
    )) as Buffer;

    // Buffers must be the same length before timingSafeEqual
    if (storedHash.length !== candidateHash.length) {
      return false;
    }

    return timingSafeEqual(storedHash, candidateHash);
  }
  async signIn(username: string, password: string): Promise<{ jwt: string }> {
    try {
      const user = await this.userService.findUnique({
        where: { username },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (user.password !== password) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const payload = {
        sub: Number(user.id),
        username: user.username,
      };

      return {
        jwt: this.jwtService.sign(payload),
      };
    } catch {
      throw new InternalServerErrorException('Unexpected error during login');
    }
  }

  async register(
    username: string,
    password: string,
    email: string,
  ): Promise<{ jwt: string }> {
    try {
      const existing = await this.userService.findUnique({
        where: { username },
        select: { id: true }, // minimal projection — we only need existence
      });

      if (existing) {
        // Generic message — do NOT reveal whether the username or email matched.
        // (OWASP A07 — no user enumeration)
        throw new ConflictException(
          'User with provided credentials already exists',
        );
      }
      const hashedPassword = await this.hashPassword(password);
      const user = await this.userService.createUnique({
        data: {
          passwordHash: hashedPassword,
          username: username,
          email: email,
        },
      });
      console.log('⚙️ ~ AuthService ~ signUp ~ user:', user);

      if (!user) {
        throw new InternalServerErrorException('User could not be created');
      }

      const payload = {
        sub: Number(user.id), // safe for BigInt
        username: user.username,
      };

      const accessToken = this.jwtService.sign(payload);

      return {
        jwt: accessToken,
      };
    } catch (error: unknown) {
      console.log('⚙️ ~ AuthService ~ signUp ~ error:', error);
      await this.userService.deleteUser({
        where: { username: username },
      });
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
}
