import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { TokenPayload } from '../interfaces/auth.entities';
import { AuthTokenService } from '../services/auth-token.service';

/**
 * Guard that extracts the JWT from a secure cookie (access_token) or from
 * the Authorization: Bearer header, verifies it, and attaches the payload to request.user.
 * Cookie is preferred when present so browser-based clients work without sending the token in headers.
 */
@Injectable()
export class JwtBearerGuard implements CanActivate {
  private static readonly COOKIE_NAME = 'access_token';

  constructor(private readonly tokenService: AuthTokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token =
      request.cookies?.[JwtBearerGuard.COOKIE_NAME] ??
      this.getTokenFromBearer(request.headers.authorization);
    if (!token) {
      throw new UnauthorizedException('Missing or invalid Authorization header or cookie');
    }
    try {
      const payload = this.tokenService.verifyAccess(token) as TokenPayload;
      (request as Request & { user: TokenPayload }).user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  private getTokenFromBearer(authHeader?: string): string | undefined {
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    return undefined;
  }
}
