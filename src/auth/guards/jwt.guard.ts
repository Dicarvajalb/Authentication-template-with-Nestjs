import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { TokenPayload } from '../interfaces/auth.entities';
import { AuthTokenService } from '../services/auth-token.service';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from 'src/common/decorators/public';

/**
 * Guard that extracts the JWT from a secure cookie (access_token) or from
 * the Authorization: Bearer header, verifies it, and attaches the payload to request.user.
 * Cookie is preferred when present so browser-based clients work without sending the token in headers.
 */
export const JWT_GUARD = Symbol('JWT_GUARD');

@Injectable()
export class JwtGuard implements CanActivate {
  private static readonly COOKIE_NAME = 'access_token';

  constructor(
    private readonly tokenService: AuthTokenService,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      // 💡 See this condition
      return true;
    }
    const request = context.switchToHttp().getRequest<Request>();
    const token =
      request.cookies?.[JwtGuard.COOKIE_NAME] ??
      this.getTokenFromBearer(request.headers.authorization);
    if (!token) {
      throw new UnauthorizedException(
        'Missing or invalid Authorization header or cookie',
      );
    }
    if (this.tokenService.decodeToken(token).type !== 'access') {
      throw new UnauthorizedException('Access denied');
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
