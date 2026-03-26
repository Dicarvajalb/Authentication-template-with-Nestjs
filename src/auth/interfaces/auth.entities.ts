export interface AuthTokens {
  access_token: string;
  refresh_token: string;
}

export type TokenType = 'refresh' | 'access';
export interface TokenPayload {
  sub: string;
  jti?: string;
  iat?: number;
  exp?: number;
  type: TokenType;
}

export interface JWTToken {
  jti: string;
  userId: string;
  type: TokenType;
  replacedByJti?: string;
  revoked?: boolean;
  expiresAt: Date;
}
