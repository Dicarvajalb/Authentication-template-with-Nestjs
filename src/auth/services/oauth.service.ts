import { HttpService } from '@nestjs/axios';
import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomUUID, createPublicKey } from 'node:crypto';
import { firstValueFrom } from 'rxjs';
import { PrismaService } from 'src/prisma/prisma.service';
import type { TokenPayload } from '../interfaces/auth.entities';
import { AuthTokenService } from './auth-token.service';
import { OAuth2Client } from 'google-auth-library';

const GoogleClient = new OAuth2Client();
type GoogleTokenResponse = {
  access_token: string;
  expires_in: number;
  id_token: string;
  scope?: string;
  token_type?: string;
  refresh_token?: string;
};

type GoogleUserInfo = {
  sub: string;
  email?: string;
  name?: string;
};

type GoogleJwks = {
  keys: Array<{
    kid: string;
    kty: string;
    alg?: string;
    use?: string;
    x5c?: string[];
  }>;
};

@Injectable()
export class OAuthGoogleService {
  private static readonly STATE_TTL_MS = 10 * 60 * 1000;
  private static readonly GOOGLE_AUTH_URL =
    'https://accounts.google.com/o/oauth2/v2/auth';
  private static readonly GOOGLE_TOKEN_URL =
    'https://oauth2.googleapis.com/token';
  private static readonly GOOGLE_USERINFO_URL =
    'https://www.googleapis.com/oauth2/v3/userinfo';
  private static readonly GOOGLE_CERTS_URL =
    'https://www.googleapis.com/oauth2/v3/certs';

  constructor(
    private readonly config: ConfigService,
    private readonly http: HttpService,
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly tokenService: AuthTokenService,
  ) {
    // Fail fast if required config is missing
    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.config.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackUrl = this.config.get<string>('GOOGLE_CALLBACK_URL');
    if (!clientId || !clientSecret || !callbackUrl) {
      throw new InternalServerErrorException(
        'Google OAuth config is missing (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_CALLBACK_URL)',
      );
    }
  }
  //Build the redirect url with Client ID, client secret and callback endpoint
  public async createAuthRedirectUrl(): Promise<{ url: string }> {
    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID')!;
    const callbackUrl = this.config.get<string>('GOOGLE_CALLBACK_URL')!;

    const state = randomUUID();
    const expiresAt = new Date(Date.now() + OAuthGoogleService.STATE_TTL_MS);

    await this.prisma.oAuthState.create({
      data: { state, expiresAt },
    });

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      access_type: 'online',
      prompt: 'consent',
    });

    return {
      url: `${OAuthGoogleService.GOOGLE_AUTH_URL}?${params.toString()}`,
    };
  }

  public async handleCallback(args: {
    code: string;
    state: string;
    linkingUserId?: string;
  }): Promise<{ token: string; expiresIn: number }> {
    await this.validateAndConsumeState(args.state);

    const tokenRes = await this.exchangeCodeForTokens(args.code);
    const idClaims = await this.verifyGoogleIdToken(tokenRes.id_token);
    const userInfo = await this.fetchUserInfo(tokenRes.access_token);

    const sub = idClaims.sub ?? userInfo.sub;
    if (!sub) {
      throw new UnauthorizedException('Invalid Google identity');
    }

    const email = userInfo.email ?? idClaims.email;
    const name = userInfo.name ?? idClaims.name ?? null;

    const user = args.linkingUserId
      ? await this.linkToExistingUser(args.linkingUserId, { sub, email, name })
      : await this.findOrCreateUser({ sub, email, name });

    const payload: TokenPayload = {
      sub: user.id,
      type: 'access',
    };

    const jwtDuration = this.config.get<number>('JWT_DURATION') ?? 6000;
    return {
      token: this.tokenService.signAccess(payload),
      expiresIn: jwtDuration,
    };
  }

  private async validateAndConsumeState(state: string): Promise<void> {
    const record = await this.prisma.oAuthState.findUnique({
      where: { state },
    });
    if (!record) {
      throw new UnauthorizedException('Invalid OAuth state');
    }
    const now = new Date();
    if (record.expiresAt <= now) {
      await this.prisma.oAuthState
        .delete({ where: { state } })
        .catch(() => undefined);
      throw new UnauthorizedException('Expired OAuth state');
    }
    // Single-use
    await this.prisma.oAuthState.delete({ where: { state } });
  }

  private async exchangeCodeForTokens(
    code: string,
  ): Promise<GoogleTokenResponse> {
    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID')!;
    const clientSecret = this.config.get<string>('GOOGLE_CLIENT_SECRET')!;
    const callbackUrl = this.config.get<string>('GOOGLE_CALLBACK_URL')!;

    const body = new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: callbackUrl,
      grant_type: 'authorization_code',
    });

    const { data } = await firstValueFrom(
      this.http.post<GoogleTokenResponse>(
        OAuthGoogleService.GOOGLE_TOKEN_URL,
        body.toString(),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        },
      ),
    );

    if (!data?.access_token || !data?.id_token) {
      throw new UnauthorizedException('Google token exchange failed');
    }
    return data;
  }

  private async fetchUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    const { data } = await firstValueFrom(
      this.http.get<GoogleUserInfo>(OAuthGoogleService.GOOGLE_USERINFO_URL, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    );
    if (!data?.sub) {
      throw new UnauthorizedException('Google userinfo invalid');
    }
    return data;
  }

  private async verifyGoogleIdToken(idToken: string): Promise<any> {
    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID')!;

    try {
      const ticket = await GoogleClient.verifyIdToken({
        idToken,
        audience: clientId,
      });

      return ticket.getPayload(); // This is the verified claims (email, sub, etc.)
    } catch (error) {
      throw new UnauthorizedException('Invalid Google ID token');
    }
  }

  private async fetchGoogleCerts(): Promise<GoogleJwks> {
    const { data } = await firstValueFrom(
      this.http.get<GoogleJwks>(OAuthGoogleService.GOOGLE_CERTS_URL),
    );
    if (!data?.keys?.length) {
      throw new UnauthorizedException('Google certs unavailable');
    }
    return data;
  }

  private async findOrCreateUser(profile: {
    sub: string;
    email?: string;
    name: string | null;
  }): Promise<{ id: string; email: string; username: string }> {
    const existing = await this.prisma.oAuthAccount.findUnique({
      where: { sub: profile.sub },
      include: { user: true },
    });
    if (existing?.user) {
      return {
        id: existing.user.id,
        email: existing.user.email,
        username: existing.user.username,
      };
    }

    if (!profile.email) {
      throw new UnauthorizedException('Google account has no email');
    }

    const username = await this.generateUniqueUsername(
      profile.email,
      profile.name,
    );

    const user = await this.prisma.user.create({
      data: {
        email: profile.email,
        username,
        passwordHash: null,
        oAuthAccount: {
          create: {
            sub: profile.sub,
            email: profile.email,
            name: profile.name ?? undefined,
          },
        },
      },
      select: { id: true, email: true, username: true },
    });
    return user;
  }

  private async linkToExistingUser(
    userId: string,
    profile: { sub: string; email?: string; name: string | null },
  ): Promise<{ id: string; email: string; username: string }> {
    const alreadyLinked = await this.prisma.oAuthAccount.findUnique({
      where: { sub: profile.sub },
      select: { userId: true },
    });
    if (alreadyLinked && alreadyLinked.userId !== userId) {
      throw new ConflictException(
        'OAuth account already linked to another user',
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, username: true },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid user');
    }

    if (!alreadyLinked) {
      if (!profile.email) {
        throw new UnauthorizedException('Google account has no email');
      }
      await this.prisma.oAuthAccount.create({
        data: {
          sub: profile.sub,
          email: profile.email,
          name: profile.name ?? undefined,
          userId,
        },
      });
    }

    return user;
  }

  private async generateUniqueUsername(
    email: string,
    name: string | null,
  ): Promise<string> {
    const base = (
      name?.trim()?.split(/\s+/)?.[0] ||
      email.split('@')[0] ||
      'user'
    )
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '');

    for (let i = 0; i < 10; i++) {
      const suffix = randomUUID().slice(0, 6);
      const candidate = `${base}_${suffix}`;
      const exists = await this.prisma.user.findUnique({
        where: { username: candidate },
        select: { id: true },
      });
      if (!exists) return candidate;
    }
    throw new InternalServerErrorException('Could not generate username');
  }
}
