import { ConfigModule } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('src/generated/prisma/client', () => ({
  Prisma: {
    PrismaClientKnownRequestError: class PrismaClientKnownRequestError extends Error {
      code?: string;
    },
  },
  PrismaClient: class PrismaClient {},
}));

import { AuthController } from '../auth/auth.controller';
import { AuthModule } from '../auth/auth.module';
import { AuthTokenService } from '../auth/services/auth-token.service';
import { OAuthGoogleService } from '../auth/services/oauth.service';
import appConfig from '../config/app.config';
import authConfig from '../config/auth.config';
import passwordConfig from '../config/password.config';
import { PrismaService } from '../prisma/prisma.service';

describe('Refresh Requirement 4.3', () => {
  let controller: AuthController;
  let tokenService: AuthTokenService;

  const prismaMock = {
    user: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
    loginAttempt: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
    },
    jWTToken: {
      create: jest.fn(),
      findUniqueOrThrow: jest.fn(),
      update: jest.fn(),
    },
    $transaction: jest.fn(),
  };

  const oauthService = {
    createAuthRedirectUrl: jest.fn(),
    handleCallback: jest.fn(),
  };

  beforeAll(async () => {
    process.env.JWT_PRIVATE_KEY =
      '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDnEa2J5modwP+i\n99aF8ZTY85+SYEb8oGz9OjtAYlPY1Hhw+dOMHmxvphCOE/yNQcmKjQCN5zku5Dix\nXKcb9JXrKLYCYatZRrxPhj44og79yBWpXLiZ1zLKg3ORuou7pNbbSrWJZrxHLV+R\n+SacQMUGN6mtwVpvuWAxl/YRUMC8BZ3qOaf4/+QTFZlsbgTZQQNrUlWsuho+pDmD\n7555m6Hl3xyRjj7ZLkYX2K8SKD6IKzuK/4UnXpYNm2Kfe9y+/98twXytXzMuaLMe\nNggIv64hGFD56JuNdULVG6f9nCHc0dfdrizsp4Djs3/q0ikWIv/srLjo44+bT7KH\nM8wa87LNAgMBAAECggEAJKu2y42MdjvgphuoiTnRekvRnYCXi3SnT1nMOPfR4DW6\nBo3zX4edhGuJsY6k9EMGSe1+MscJGXLBN46he6uJllgv6HlZIPI7pPBEVCcN84Mr\nQuVS66FOL3sEnpJJJkavDX7SCCQMicw+4FL26HHUAtxXGpr2sAfupvg7pjxXVg9N\n8OJSyh+yNfbjyXuGuH1x2SHbfILFGjEhNYvh15m/vxhwD8o25Rqgje/qwAsoCDye\nJQwllh6IgiAZBkGZ6yUEfTcYbOi6TbBdxA19CN7lWHgX/+jMvmu0eivjbeFZnL0g\nAt5OiDlL350qRhW0gSvYYjXx4DKZbANQt69uaSUPKQKBgQD1MpkTinp/0u0tkEiC\ny/2o0FB1P+/0fYCkUSgUZqo+HlyZLzQemcuWeRAQjv0d1jdpRSV/cV4K2Vg7t5K4\nkgp48m7w8pQlzulRkkTxIi13A7zkdwqGKIc+IAiye9OKrD8uV0msIJ7XhsCKmlOO\nDjBDH9F/m/xZp9SvILItq/BwlQKBgQDxP7vosQopVxOsCXPUZW/yCfEkg/50a6Th\nao04W3PPCXauuSBu6stLzeg5f8SXehT9uvMrAAsGqYAfUoV+tfJ8STPTFy7IBrfg\nZRbNL7ZTBHyPit2f290t1WONxb9GRsZR7OA2rCBi/rcDu1rlK5enSu51DXZS2dI2\nsGL11BuTWQKBgQCRPVt3O7u8I5DiQGjzMSob6Oj/ytO0GvMsYfY/v2BwU0O+aTuS\nNL9nbmaZqFk+ZzmDXbYMe3adLokZNm/ubHNPmSsmBkrC6oFCFEZKH1iW+tvU6L6P\nIUqa/haowrhXmBgEtyeokdoFCIjckPWVW8oyuJI76IXeBY/x/IgOjZ5q0QKBgFVq\nn3mP1W01q31qC1zUXYJxCrRHF7zYsBQvybh+iM5xJ1hNq7IZ58j7KpHRLyYCz5PW\nsWo0JbNCKF7utN1cRnLC6FqBBstDta75m80ia4eROxkHrdh/3BvyRcFYlpSnUmiH\nWguBfiYO0XW8zD3/5T4SRcOj9JT5EnjSkvc/FlRhAoGBAPOHWTcCU55E/SHkdvKL\nzYJINuVWnYpZwBSJ4TQbqte6H1Lk3WbPjEEhnmJ6OJnvt6Gr/PIe1KBksiwVQVtR\nzWpL/8ZrLIFppww2dcLzdbHWHnPLT3LYzvaqF5oqcrfBUnPVbuZULTjNLL/vrbp+\nkyJv0k0wkAnhkAUglOAjHAhC\n-----END PRIVATE KEY-----';
    process.env.JWT_PUBLIC_KEY =
      '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5xGtieZqHcD/ovfWhfGU\n2POfkmBG/KBs/To7QGJT2NR4cPnTjB5sb6YQjhP8jUHJio0Ajec5LuQ4sVynG/SV\n6yi2AmGrWUa8T4Y+OKIO/cgVqVy4mdcyyoNzkbqLu6TW20q1iWa8Ry1fkfkmnEDF\nBjeprcFab7lgMZf2EVDAvAWd6jmn+P/kExWZbG4E2UEDa1JVrLoaPqQ5g++eeZuh\n5d8ckY4+2S5GF9ivEig+iCs7iv+FJ16WDZtin3vcvv/fLcF8rV8zLmizHjYICL+u\nIRhQ+eibjXVC1Run/Zwh3NHX3a4s7KeA47N/6tIpFiL/7Ky46OOPm0+yhzPMGvOy\nzQIDAQAB\n-----END PUBLIC KEY-----';
    process.env.JWT_DURATION = '900';
    process.env.JWT_REFRESH_DURATION = '604800';
    process.env.PASSWORD_REGEX =
      '^(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{10,}$';
    process.env.PASSWORD_ERROR_MESSAGE =
      'Password must be at least 10 characters and include one uppercase letter, one number, and one symbol.';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          cache: true,
          load: [appConfig, authConfig, passwordConfig],
        }),
        AuthModule,
      ],
    })
      .overrideProvider(PrismaService)
      .useValue(prismaMock)
      .overrideProvider(OAuthGoogleService)
      .useValue(oauthService)
      .compile();

    controller = moduleFixture.get(AuthController);
    tokenService = moduleFixture.get(AuthTokenService);
  });

  beforeEach(() => {
    jest.clearAllMocks();
    prismaMock.$transaction.mockResolvedValue(undefined);
  });

  it('rotates the refresh token and issues a new token pair', async () => {
    const refreshToken = tokenService.signRefresh({
      sub: 'user-1',
      type: 'refresh',
      jti: 'refresh-jti-1',
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    });

    prismaMock.jWTToken.findUniqueOrThrow.mockResolvedValue({
      jti: 'refresh-jti-1',
      type: 'refresh',
      userId: 'user-1',
      revoked: false,
      replacedByJti: null,
      expiresAt: new Date(Date.now() + 60_000),
    });
    prismaMock.jWTToken.create.mockResolvedValue(undefined);
    const response = {
      cookie: jest.fn(),
    } as any;

    const tokens = await controller.refreshToken(response, refreshToken);

    expect(tokens.access_token).toEqual(expect.any(String));
    expect(tokens.refresh_token).toEqual(expect.any(String));
    expect(tokens.access_token).not.toEqual(tokens.refresh_token);
    expect(prismaMock.jWTToken.create).toHaveBeenCalledTimes(2);
    expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
    expect(response.cookie).toHaveBeenCalledTimes(2);
  });

  it('rejects access tokens used on the refresh endpoint', async () => {
    const accessToken = tokenService.signAccess({
      sub: 'user-1',
      type: 'access',
      jti: 'access-jti-1',
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    });

    await expect(
      controller.refreshToken(
        {
          cookie: jest.fn(),
        } as any,
        accessToken,
      ),
    ).rejects.toThrow(new UnauthorizedException());

    expect(prismaMock.jWTToken.findUniqueOrThrow).not.toHaveBeenCalled();
  });
});
