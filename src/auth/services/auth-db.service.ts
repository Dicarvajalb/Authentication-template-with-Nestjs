import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserEntity } from 'src/user/interfaces/user.entities';
import type {
  AuthDBI,
  LoginAttemptSnapshot,
} from '../interfaces/auth.utilities';
import { JWTToken, TokenType } from '../interfaces/auth.entities';

@Injectable()
export class AuthDBService implements AuthDBI {
  constructor(private readonly prisma: PrismaService) {}

  async createUserWithTokens(data: {
    user: UserEntity;
    accessToken: JWTToken;
    refreshToken: JWTToken;
  }): Promise<UserEntity> {
    const createdUser = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          passwordHash: data.user.password,
        },
      });

      await tx.jWTToken.create({
        data: {
          ...data.accessToken,
        },
      });

      await tx.jWTToken.create({
        data: {
          ...data.refreshToken,
        },
      });

      return user;
    });

    return {
      id: createdUser.id,
      email: createdUser.email,
      username: createdUser.username,
      password: createdUser.passwordHash || '',
    };
  }

  async findLoginAttemptByUserId(
    userId: string,
  ): Promise<LoginAttemptSnapshot | null> {
    const attempt = await this.prisma.loginAttempt.findUnique({
      where: { userId },
    });
    if (!attempt) return null;
    return {
      failedCount: attempt.failedCount,
      lockedUntil: attempt.lockedUntil,
    };
  }

  async upsertLoginAttempt(
    userId: string,
    data: { failedCount: number; lockedUntil: Date | null },
  ): Promise<void> {
    const now = new Date();
    await this.prisma.loginAttempt.upsert({
      where: { userId },
      create: {
        userId,
        failedCount: data.failedCount,
        lockedUntil: data.lockedUntil,
      },
      update: {
        failedCount: data.failedCount,
        lockedUntil: data.lockedUntil,
        updatedAt: now,
      },
    });
  }

  async saveToken(token: JWTToken): Promise<void> {
    await this.prisma.jWTToken.create({
      data: {
        ...token,
      },
    });
  }
  async updateAllRevokedByUserId(
    userId: string,
    newRevoked: boolean,
  ): Promise<void> {
    await this.prisma.jWTToken.updateMany({
      where: { userId },
      data: {
        revoked: newRevoked,
      },
    });
    return;
  }
  async findToken(id: string): Promise<JWTToken> {
    const storedToken = await this.prisma.jWTToken.findUniqueOrThrow({
      where: { jti: id },
    });
    return {
      expiresAt: storedToken.expiresAt,
      jti: storedToken.jti,
      type: storedToken.type as TokenType,
      userId: storedToken.userId,
      replacedByJti: storedToken.replacedByJti || undefined,
      revoked: storedToken.revoked || undefined,
    };
  }
  async revokeAndSaveTokenTransaction(
    oldJti: string,
    newToken: JWTToken,
  ): Promise<void> {
    await this.prisma.$transaction([
      this.prisma.jWTToken.update({
        where: { jti: oldJti },
        data: {
          revoked: true,
          replacedByJti: newToken.jti,
        },
      }),
      this.prisma.jWTToken.create({ data: { ...newToken } }),
    ]);
  }

  async deleteExpiredTokens(now: Date): Promise<number> {
    const { count } = await this.prisma.jWTToken.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    });

    return count;
  }
}
