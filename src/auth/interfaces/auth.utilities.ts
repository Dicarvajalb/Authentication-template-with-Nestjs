import { UserEntity } from 'src/user/interfaces/user.entities';
import { AuthTokens, TokenPayload } from './auth.entities';

/** Injection token for AuthDBI (DIP: depend on abstraction, not concrete class). */
export const AUTH_DB = Symbol('AUTH_DB');

/** Snapshot of login attempt state for auth logic; avoids leaking Prisma/DB types. */
export interface LoginAttemptSnapshot {
  failedCount: number;
  lockedUntil: Date | null;
}

export interface AuthDBI {
  findLoginAttemptByUserId(userId: string): Promise<LoginAttemptSnapshot | null>;
  upsertLoginAttempt(
    userId: string,
    data: { failedCount: number; lockedUntil: Date | null },
  ): Promise<void>;
}

export interface AuthServiceI {
  register(
    username: string,
    email: string,
    password: string,
  ): Promise<{ user: UserEntity; tokens: AuthTokens }>;
  login(email: string, password: string): Promise<AuthTokens>;
  //refresh(refreshToken: string): Promise<AuthTokens>;
  logout(userId: string): Promise<void>;
  changePassword(token: string, current: string, next: string): Promise<UserEntity>;
}
export interface AuthPasswordServiceI {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}
export interface AuthTokenServiceI {
  signAccess(payload: TokenPayload): string;
  //signRefresh(payload: TokenPayload): string;
  verifyAccess(token: string): TokenPayload;
  //verifyRefresh(token: string): TokenPayload;
  //refreshTtlMs(): number;
}
