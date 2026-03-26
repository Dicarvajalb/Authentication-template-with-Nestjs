import { UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { JwtGuard } from '../auth/guards/jwt.guard';
import { AUTH_DB } from '../auth/interfaces/auth.utilities';
import { AuthTokenService } from '../auth/services/auth-token.service';

describe('JwtGuard token revocation', () => {
  let guard: JwtGuard;

  const tokenService = {
    decodeToken: jest.fn(),
    verifyAccess: jest.fn(),
  };

  const authDb = {
    findToken: jest.fn(),
  };

  const reflector = {
    getAllAndOverride: jest.fn(),
  };

  const createContext = (token: string) =>
    ({
      switchToHttp: () => ({
        getRequest: () => ({
          cookies: { access_token: token },
          headers: {},
        }),
      }),
      getHandler: jest.fn(),
      getClass: jest.fn(),
    }) as any;

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      providers: [
        JwtGuard,
        { provide: AuthTokenService, useValue: tokenService },
        { provide: AUTH_DB, useValue: authDb },
        { provide: Reflector, useValue: reflector },
      ],
    }).compile();

    guard = moduleFixture.get(JwtGuard);
    reflector.getAllAndOverride.mockReturnValue(false);
  });

  it('rejects revoked access tokens', async () => {
    tokenService.decodeToken.mockReturnValue({ type: 'access' });
    tokenService.verifyAccess.mockReturnValue({
      sub: 'user-1',
      jti: 'jti-1',
      type: 'access',
    });
    authDb.findToken.mockResolvedValue({
      jti: 'jti-1',
      userId: 'user-1',
      type: 'access',
      revoked: true,
      expiresAt: new Date(),
    });

    await expect(guard.canActivate(createContext('token'))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('allows non-revoked access tokens', async () => {
    tokenService.decodeToken.mockReturnValue({ type: 'access' });
    tokenService.verifyAccess.mockReturnValue({
      sub: 'user-1',
      jti: 'jti-2',
      type: 'access',
    });
    authDb.findToken.mockResolvedValue({
      jti: 'jti-2',
      userId: 'user-1',
      type: 'access',
      revoked: false,
      expiresAt: new Date(),
    });

    await expect(guard.canActivate(createContext('token'))).resolves.toBe(true);
    expect(authDb.findToken).toHaveBeenCalledWith('jti-2');
  });
});
