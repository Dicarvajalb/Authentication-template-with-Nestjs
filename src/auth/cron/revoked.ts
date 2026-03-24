import { Inject, Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { AUTH_DB, type AuthDBI } from '../interfaces/auth.utilities';

const JWT_PURGE_CRON = process.env.JWT_PURGE_CRON?.trim() || '0 0 * * *';

@Injectable()
export class RevokedCronToken {
  private readonly logger = new Logger(RevokedCronToken.name);

  constructor(
    @Inject(AUTH_DB)
    readonly authDBI: AuthDBI,
  ) {}

  @Cron(JWT_PURGE_CRON)
  async handleCron(): Promise<void> {
    const deletedCount = await this.authDBI.deleteExpiredTokens(new Date());

    this.logger.log(
      `Deleted ${deletedCount} expired JWT token rows using cron "${JWT_PURGE_CRON}"`,
    );
  }
}
