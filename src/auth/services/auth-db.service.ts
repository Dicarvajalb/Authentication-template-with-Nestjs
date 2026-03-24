import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import type {
  AuthDBI,
  LoginAttemptSnapshot,
} from '../interfaces/auth.utilities';
import { JWTToken, TokenType } from '../interfaces/auth.entities';

@Injectable()
export class AuthDBService implements AuthDBI {
  constructor(private readonly prisma: PrismaService) {}

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

  async deleteAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.prisma.jWTToken.deleteMany({
      where: { userId },
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
      where: { jti: userId },
      data: {
        revoked: newRevoked,
      },
    });
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
      this.prisma.jWTToken.delete({ where: { jti: oldJti } }),
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
