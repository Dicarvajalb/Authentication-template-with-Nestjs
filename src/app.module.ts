import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ProfilesModule } from './profiles/profiles.module';
import { UserModule } from './user/user.module';
import { JWT_GUARD, JwtGuard } from './auth/guards/jwt.guard';
import appConfig from './config/app.config';
import authConfig from './config/auth.config';
import databaseConfig from './config/database.config';
import oauthConfig from './config/oauth.config';
import passwordConfig from './config/password.config';
import { getEnvFilePaths } from './config/env.utils';
import { validate } from './config/env.validation';
import { Reflector } from '@nestjs/core';

@Module({
  imports: [
    ProfilesModule,
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
  ],
  controllers: [AppController],
  providers: [AppService, { provide: JWT_GUARD, useClass: JwtGuard }],
})
export class AppModule {}
