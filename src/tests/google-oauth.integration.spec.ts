import { of } from 'rxjs';
import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';

jest.mock('src/generated/prisma/client', () => ({
  Prisma: {
    PrismaClientKnownRequestError: class PrismaClientKnownRequestError extends Error {
      code?: string;
    },
  },
  PrismaClient: class PrismaClient {},
}));

const getPayload = jest.fn();
const verifyIdToken = jest.fn();

jest.mock('google-auth-library', () => ({
  OAuth2Client: jest.fn().mockImplementation(() => ({
    verifyIdToken,
  })),
}));

import authConfig from '../config/auth.config';
import oauthConfig from '../config/oauth.config';
import { PrismaService } from '../prisma/prisma.service';
import { OAuthGoogleService } from '../auth/services/oauth.service';
import { AuthService } from '../auth/services/auth.service';

describe('Google OAuth 3.1', () => {
  let service: OAuthGoogleService;

  const http = {
    post: jest.fn(),
    get: jest.fn(),
  };

  const prisma = {
    oAuthState: {
      create: jest.fn(),
      findUnique: jest.fn(),
      delete: jest.fn(),
    },
    oAuthAccount: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
    user: {
      create: jest.fn(),
      findUnique: jest.fn(),
    },
  };

  const authService = {
    issueTokenPairForUser: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      providers: [
        OAuthGoogleService,
        { provide: HttpService, useValue: http },
        { provide: PrismaService, useValue: prisma },
        { provide: AuthService, useValue: authService },
        {
          provide: oauthConfig.KEY,
          useValue: {
            googleClientId: 'google-client-id',
            googleClientSecret: 'google-client-secret',
            googleCallbackUrl: 'http://localhost:3001/auth/google/callback',
          },
        },
        {
          provide: authConfig.KEY,
          useValue: {
            jwtDurationMs: 900,
          },
        },
      ],
    }).compile();

    service = moduleFixture.get(OAuthGoogleService);
  });

  it('creates a Google authorization URL and stores single-use state', async () => {
    prisma.oAuthState.create.mockResolvedValue(undefined);

    const response = await service.createAuthRedirectUrl();

    expect(prisma.oAuthState.create).toHaveBeenCalledTimes(1);
    expect(response.url).toContain(
      'https://accounts.google.com/o/oauth2/v2/auth?',
    );
    expect(response.url).toContain('client_id=google-client-id');
    expect(response.url).toContain(
      'redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fauth%2Fgoogle%2Fcallback',
    );
    expect(response.url).toContain('response_type=code');
    expect(response.url).toContain('scope=openid+email+profile');
    expect(response.url).toContain('state=');
  });

  it('consumes OAuth state, verifies Google identity and issues the standard token pair', async () => {
    prisma.oAuthState.findUnique.mockResolvedValue({
      state: 'oauth-state',
      expiresAt: new Date(Date.now() + 60_000),
    });
    prisma.oAuthState.delete.mockResolvedValue(undefined);
    http.post.mockReturnValue(
      of({
        data: {
          access_token: 'google-access',
          id_token: 'google-id-token',
          expires_in: 3600,
        },
      }),
    );
    http.get.mockReturnValueOnce(
      of({
        data: {
          sub: 'google-sub',
          email: 'diego@example.com',
          name: 'Diego',
        },
      }),
    );
    getPayload.mockReturnValue({
      sub: 'google-sub',
      email: 'diego@example.com',
      name: 'Diego',
    });
    verifyIdToken.mockResolvedValue({ getPayload });
    prisma.oAuthAccount.findUnique.mockResolvedValue(null);
    prisma.user.findUnique.mockResolvedValue(null);
    prisma.user.create.mockResolvedValue({
      id: 'user-1',
      email: 'diego@example.com',
      username: 'diego_abcd12',
    });
    authService.issueTokenPairForUser.mockResolvedValue({
      access_token: 'app-access',
      refresh_token: 'app-refresh',
    });

    const response = await service.handleCallback({
      code: 'oauth-code',
      state: 'oauth-state',
    });

    expect(prisma.oAuthState.delete).toHaveBeenCalledWith({
      where: { state: 'oauth-state' },
    });
    expect(http.post).toHaveBeenCalledTimes(1);
    expect(verifyIdToken).toHaveBeenCalledWith({
      idToken: 'google-id-token',
      audience: 'google-client-id',
    });
    expect(prisma.user.create).toHaveBeenCalledTimes(1);
    expect(authService.issueTokenPairForUser).toHaveBeenCalledWith('user-1');
    expect(response).toEqual({
      access_token: 'app-access',
      refresh_token: 'app-refresh',
    });
  });
});
