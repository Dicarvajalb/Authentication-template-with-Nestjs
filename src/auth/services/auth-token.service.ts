import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from '../interfaces/auth.entities';
import { AuthTokenServiceI } from '../interfaces/auth.utilities';

@Injectable()
export class AuthTokenService implements AuthTokenServiceI {
  constructor(private readonly jwtService: JwtService) {}
  signAccess(payload: TokenPayload): string {
    return this.jwtService.sign(payload);
  }
  verifyAccess(token: string): TokenPayload {
    return this.jwtService.verify(token);
  }
}
