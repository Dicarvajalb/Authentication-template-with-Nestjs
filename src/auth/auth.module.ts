import { Module } from '@nestjs/common';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from 'src/prisma/prisma.module';
import { UserModule } from 'src/user/user.module';
import { RevokedCronToken } from './cron/revoked';
import { AUTH_DB } from './interfaces/auth.utilities';
import { OAUTH_SERVICE } from './interfaces/oauth.utilities';
import { AuthController } from './auth.controller';
import { LoginValidationPipe } from './pipes/login.pipe';
import { RegisterValidationPipe } from './pipes/register.pipe';
import { AuthDBService } from './services/auth-db.service';
import { AuthService } from './services/auth.service';
import { AuthTokenService } from './services/auth-token.service';
import { AuthPasswordService } from './services/auth-password.service';
import { ChangePassValidationPipe } from './pipes/change-password.pipe';
import { OAuthGoogleService } from './services/oauth.service';
import authConfig from 'src/config/auth.config';

@Module({
  controllers: [AuthController],
  exports: [AuthTokenService, AUTH_DB, OAUTH_SERVICE],
  providers: [
    AuthService,
    AuthTokenService,
    AuthPasswordService,
    AuthDBService,
    OAuthGoogleService,
    RevokedCronToken,
    { provide: AUTH_DB, useClass: AuthDBService },
    { provide: OAUTH_SERVICE, useExisting: OAuthGoogleService },
    LoginValidationPipe,
    RegisterValidationPipe,
    ChangePassValidationPipe,
  ],
  imports: [
    PrismaModule,
    UserModule,
    HttpModule,
    ScheduleModule.forRoot(),
    ConfigModule.forFeature(authConfig),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule.forFeature(authConfig)],
      inject: [authConfig.KEY],
      useFactory: (config: ConfigType<typeof authConfig>) => {
        return {
          publicKey: config.jwtPublicKey,
          privateKey: config.jwtPrivateKey,
          signOptions: {
            algorithm: 'RS256',
          },
        };
      },
    }),
  ],
})
export class AuthModule {}
