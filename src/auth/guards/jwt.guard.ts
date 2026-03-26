import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { TokenPayload } from '../interfaces/auth.entities';
import { AUTH_DB, type AuthDBI } from '../interfaces/auth.utilities';
import { AuthTokenService } from '../services/auth-token.service';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from 'src/common/decorators/public';

/**
 * Guard that extracts the JWT from the secure access_token cookie, verifies it,
 * checks revocation state in storage, and attaches the payload to request.user.
 */

@Injectable()
export class JwtGuard implements CanActivate {
  private static readonly COOKIE_NAME = 'access_token';

  constructor(
    private readonly tokenService: AuthTokenService,
    @Inject(AUTH_DB) private readonly authDb: AuthDBI,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    const request = context.switchToHttp().getRequest<Request>();
    const token = request.cookies?.[JwtGuard.COOKIE_NAME];
    if (!token) {
      throw new UnauthorizedException('Missing access token cookie');
    }
    try {
      const payload = this.tokenService.verifyAccess(token) as TokenPayload;
      if (payload.type !== 'access') {
        throw new UnauthorizedException('Access denied');
      }
      if (!payload.jti) {
        throw new UnauthorizedException('Invalid or expired token');
      }
      const storedToken = await this.authDb.findToken(payload.jti);
      if (storedToken.revoked) {
        throw new UnauthorizedException('Token revoked');
      }
      (request as Request & { user: TokenPayload }).user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
