export interface AuthTokens {
  token: string;
  expiresIn: number; // seconds
}

export interface TokenPayload {
  sub: string;
  email: string;
  iat?: number;
  exp?: number;
}
