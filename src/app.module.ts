import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';
import { JwtGuard } from './auth/guards/jwt.guard';
import appConfig from './config/app.config';
import authConfig from './config/auth.config';
import databaseConfig from './config/database.config';
import oauthConfig from './config/oauth.config';
import passwordConfig from './config/password.config';
import { getEnvFilePaths } from './config/env.utils';
import { validate } from './config/env.validation';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    AuthModule,
    UserModule,
    PrismaModule,
    Reflector,
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      envFilePath: getEnvFilePaths(),
      load: [
        appConfig,
        authConfig,
        databaseConfig,
        oauthConfig,
        passwordConfig,
      ],
      validate,
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 1000,
        limit: 3,
        blockDuration: 10000,
      },
    ]),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_GUARD, useClass: JwtGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
