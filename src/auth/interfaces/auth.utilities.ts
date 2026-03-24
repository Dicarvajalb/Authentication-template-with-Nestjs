import { UserEntity } from 'src/user/interfaces/user.entities';
import { AuthTokens, JWTToken, TokenPayload } from './auth.entities';

/** Injection token for AuthDBI (DIP: depend on abstraction, not concrete class). */
export const AUTH_DB = Symbol('AUTH_DB');

/** Snapshot of login attempt state for auth logic; avoids leaking Prisma/DB types. */
export interface LoginAttemptSnapshot {
  failedCount: number;
  lockedUntil: Date | null;
}

export interface AuthDBI {
  findLoginAttemptByUserId(
    userId: string,
  ): Promise<LoginAttemptSnapshot | null>;
  upsertLoginAttempt(
    userId: string,
    data: { failedCount: number; lockedUntil: Date | null },
  ): Promise<void>;
  deleteAllRefreshTokensForUser(userId: string): Promise<void>;

  findToken(id: string): Promise<JWTToken>;
  saveToken(token: JWTToken): Promise<void>;
  revokeAndSaveTokenTransaction(
    oldJti: string,
    newToken: JWTToken,
  ): Promise<void>;
  updateAllRevokedByUserId(userId: string, newRevoked: boolean): Promise<void>;
  deleteExpiredTokens(now: Date): Promise<number>;
}

export interface AuthServiceI {
  register(
    username: string,
    email: string,
    password: string,
  ): Promise<{ user: UserEntity; tokens: AuthTokens }>;
  login(email: string, password: string): Promise<AuthTokens>;
  refresh(refreshToken: string): Promise<AuthTokens>;
  logout(userId: string): Promise<void>;
  changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void>;
}
export interface AuthPasswordServiceI {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}
export interface AuthTokenServiceI {
  signAccess(payload: TokenPayload): string;
  //signRefresh(payload: TokenPayload): string;
  verifyAccess(token: string, expiresInMls?: number): TokenPayload;
  //verifyRefresh(token: string): TokenPayload;
  //refreshTtlMs(): number;
}
