import { BadRequestException, ConflictException } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';

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
import { ChangePassValidationPipe } from '../auth/pipes/change-password.pipe';
import { RegisterValidationPipe } from '../auth/pipes/register.pipe';
import { OAuthGoogleService } from '../auth/services/oauth.service';
import appConfig from '../config/app.config';
import authConfig from '../config/auth.config';
import passwordConfig from '../config/password.config';
import { PrismaService } from '../prisma/prisma.service';

describe('Registration Requirement 2.1', () => {
  let controller: AuthController;
  let registerValidationPipe: RegisterValidationPipe;

  const prismaMock = {
    user: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
    jWTToken: {
      create: jest.fn(),
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
    registerValidationPipe = moduleFixture.get(RegisterValidationPipe);
    moduleFixture.get(ChangePassValidationPipe);
  });

  beforeEach(() => {
    jest.clearAllMocks();

    prismaMock.$transaction.mockImplementation(async (callback) =>
      callback(prismaMock),
    );
  });

  it('accepts a RegisterDto and returns access_token plus refresh_token', async () => {
    const payload = registerValidationPipe.transform({
      email: 'diego@example.com',
      username: 'diego_123',
      password: 'StrongPass1!',
    });

    prismaMock.user.findFirst.mockResolvedValue(null);
    prismaMock.user.create.mockImplementation(async ({ data }) => ({
      id: data.id,
      username: data.username,
      email: data.email,
      passwordHash: data.passwordHash,
    }));
    prismaMock.jWTToken.create.mockResolvedValue(undefined);

    const response = await controller.register(payload, {
      cookie: jest.fn(),
    } as any);

    expect(response.access_token).toEqual(expect.any(String));
    expect(response.refresh_token).toEqual(expect.any(String));
    expect(response.access_token).not.toEqual(response.refresh_token);
    expect(prismaMock.user.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.user.create.mock.calls[0][0].data).toMatchObject({
      username: 'diego_123',
      email: 'diego@example.com',
      passwordHash: expect.any(String),
    });
    expect(prismaMock.user.create.mock.calls[0][0].data.passwordHash).not.toBe(
      'StrongPass1!',
    );
    expect(prismaMock.user.create.mock.calls[0][0].data.passwordHash).toContain(
      ':',
    );
    expect(prismaMock.jWTToken.create).toHaveBeenCalledTimes(2);
  });

  it('rejects duplicate email or username with ConflictException', async () => {
    const payload = registerValidationPipe.transform({
      email: 'diego@example.com',
      username: 'diego_123',
      password: 'StrongPass1!',
    });

    prismaMock.user.findFirst.mockResolvedValue({
      id: 'existing-user',
      email: 'diego@example.com',
      username: 'diego_123',
      passwordHash: 'salt:hash',
    });

    await expect(
      controller.register(payload, {
        cookie: jest.fn(),
      } as any),
    ).rejects.toThrow(ConflictException);
    expect(prismaMock.user.create).not.toHaveBeenCalled();
    expect(prismaMock.jWTToken.create).not.toHaveBeenCalled();
  });

  it('rejects an invalid password before any DB call', async () => {
    expect(() =>
      registerValidationPipe.transform({
        email: 'diego123@example.com',
        username: 'diego_123;_;!',
        password: 'weakpass',
      }),
    ).toThrow(BadRequestException);

    expect(prismaMock.user.findFirst).not.toHaveBeenCalled();
    expect(prismaMock.user.create).not.toHaveBeenCalled();
    expect(prismaMock.jWTToken.create).not.toHaveBeenCalled();
  });
});
