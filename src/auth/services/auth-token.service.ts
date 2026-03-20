import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from '../interfaces/auth.entities';
import { AuthTokenServiceI } from '../interfaces/auth.utilities';

@Injectable()
export class AuthTokenService implements AuthTokenServiceI {
  constructor(private readonly jwtService: JwtService) {}
  signAccess(payload: TokenPayload, expiresInMls?: number): string {
    return this.jwtService.sign(payload, { expiresIn: expiresInMls });
  }
  verifyAccess(token: string): TokenPayload {
    return this.jwtService.verify(token);
  }
  decodeToken(token: string): TokenPayload {
    return this.jwtService.decode(token);
  }
}
