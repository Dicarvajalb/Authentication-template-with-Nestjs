import { UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { AuthTokenService } from '../auth/services/auth-token.service';

describe('AuthTokenService 4.2', () => {
  let service: AuthTokenService;

  const jwtService = {
    sign: jest.fn(),
    verify: jest.fn(),
    decode: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      providers: [
        AuthTokenService,
        { provide: JwtService, useValue: jwtService },
      ],
    }).compile();

    service = moduleFixture.get(AuthTokenService);
  });

  it('verifies tokens with RS256 explicitly', () => {
    jwtService.verify.mockReturnValue({
      sub: 'user-1',
      jti: 'jti-1',
      type: 'access',
    });

    const payload = service.verifyAccess('token');

    expect(jwtService.verify).toHaveBeenCalledWith('token', {
      algorithms: ['RS256'],
    });
    expect(payload).toEqual({
      sub: 'user-1',
      jti: 'jti-1',
      type: 'access',
    });
  });

  it('throws UnauthorizedException when verification fails', () => {
    jwtService.verify.mockImplementation(() => {
      throw new Error('bad token');
    });

    expect(() => service.verifyAccess('token')).toThrow(UnauthorizedException);
  });
});
