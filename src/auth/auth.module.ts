import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { PrismaModule } from 'src/prisma/prisma.module';
import { UserModule } from 'src/user/user.module';
import { AUTH_DB } from './interfaces/auth.utilities';
import { AuthController } from './auth.controller';
import { LoginValidationPipe } from './pipes/login.pipe';
import { RegisterValidationPipe } from './pipes/register.pipe';
import { AuthDBService } from './services/auth-db.service';
import { AuthService } from './services/auth.service';
import { AuthTokenService } from './services/auth-token.service';
import { AuthPasswordService } from './services/auth-password.service';
import { JwtBearerGuard } from './guards/jwt.guard';
import { ChangePassValidationPipe } from './pipes/change-password.pipe';
import { OAuthGoogleService } from './services/oauth.service';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthTokenService,
    AuthPasswordService,
    AuthDBService,
    OAuthGoogleService,
    JwtBearerGuard,
    { provide: AUTH_DB, useClass: AuthDBService },
    LoginValidationPipe,
    RegisterValidationPipe,
    ChangePassValidationPipe,
  ],
  imports: [
    PrismaModule,
    UserModule,
    HttpModule,
    JwtModule.registerAsync({
      global: true,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        console.log(configService.get<string>('JWT_DURATION'));
        return {
          secret: configService.get<string>('JWT_SECRET'),
          signOptions: {
            expiresIn: configService.get<number>('JWT_DURATION') || 6000,
            algorithm: 'RS256',
          }, // 10 min
        };
      },
    }),
  ],
})
export class AuthModule {}
