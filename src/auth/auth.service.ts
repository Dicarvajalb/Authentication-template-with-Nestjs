import {
  ConflictException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from 'src/generated/prisma/client';
import { UserService } from 'src/user/user.service';
import { AuthDTO } from './dto/sign.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async signIn(username: string, password: string): Promise<AuthDTO> {
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
        access_token: this.jwtService.sign(payload),
      };
    } catch {
      throw new InternalServerErrorException('Unexpected error during login');
    }
  }

  async signUp(username: string, password: string): Promise<AuthDTO> {
    try {
      const user = await this.userService.createUnique({
        data: { password: password, username: username },
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
        access_token: accessToken,
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
