import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import type {
  AuthDBI,
  LoginAttemptSnapshot,
} from '../interfaces/auth.utilities';
import { RefreshToken } from '../interfaces/auth.entities';

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
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }

  async saveRefreshToken(token: RefreshToken): Promise<void> {
    await this.prisma.refreshToken.create({
      data: {
        ...token,
      },
    });
  }
  async findRefreshToken(id: string): Promise<RefreshToken> {
    const storedToken = await this.prisma.refreshToken.findUniqueOrThrow({
      where: { jti: id },
    });
    return {
      expiresAt: storedToken.expiresAt,
      jti: storedToken.jti,
      userId: storedToken.userId,
      replacedByJti: storedToken.replacedByJti || undefined,
      revoked: storedToken.revoked || undefined,
    };
  }
  async revokeAndSaveTokenTransaction(
    oldJti: string,
    newToken: RefreshToken,
  ): Promise<void> {
    const result = await this.prisma.$transaction([
      this.prisma.refreshToken.delete({ where: { jti: oldJti } }),
      this.prisma.refreshToken.create({ data: { ...newToken } }),
    ]);
  }
}
