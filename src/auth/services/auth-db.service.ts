import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import type { AuthDBI, LoginAttemptSnapshot } from '../interfaces/auth.utilities';

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
}
