# Security Module — Functional Requirements

**Stack:** Node.js / TypeScript · NestJS · Prisma · PostgreSQL
**Focus:** Authentication (authN) — Credentials, JWT, Google OAuth 2.0

**Intended Use:** Open-source GitHub template

## SOLID map

| Principle | Where                                                                                                                                        |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **S**RP   | One class, one job — `PasswordService` hashes, `TokenService` signs, `AuthService` orchestrates                                              |
| **O**CP   | New auth strategy → new guard/service file. New role/resource → add a row to the map in `permission.service.ts`. Zero edits to existing code |
| **L**SP   | `UserDBService` satisfies `UserDBI`; swap in any alternative and nothing breaks                                                              |
| **I**SP   | Small interfaces pattern (`user.utilities.ts`, `auth.utilities.ts`) — no consumer is forced to implement unused methods                      |
| **D**IP   | `auth.module.ts` is the only place concrete classes are named. Every service & guard depends on a `Symbol` token, not a class                |

---

## 1. Overview

This module provides a reusable, production-grade **authentication layer** built as a NestJS dynamic module. It supports two login flows — username/password and Google OAuth 2.0 — and manages sessions exclusively through JWT access/refresh token pairs. Security controls are designed to mitigate the **OWASP Top 10** risks relevant to authentication systems. All persistence is handled by **Prisma + PostgreSQL**. The module relies only on official NestJS packages plus the Google OAuth 2.0 authorization code flow (no Passport).

---

## 1.1 Approved Dependencies

| Purpose           | Package                                                          |
| ----------------- | ---------------------------------------------------------------- |
| Framework         | `@nestjs/common`, `@nestjs/core`, `@nestjs/platform-express`     |
| JWT               | `@nestjs/jwt`                                                    |
| Config            | `@nestjs/config`                                                 |
| Rate limiting     | `@nestjs/throttler`                                              |
| Caching           | `@nestjs/cache-manager`                                          |
| Scheduled tasks   | `@nestjs/schedule`                                               |
| Events            | `@nestjs/event-emitter`                                          |
| Validation        | `class-validator`, `class-transformer` _(NestJS peer deps)_      |
| Database          | `prisma`, `@prisma/client`                                       |
| Password hashing  | Node.js built-in `crypto` (`bcrypt` + `randomBytes`)             |
| Google OAuth HTTP | Node.js built-in `https` / NestJS `HttpModule` (`@nestjs/axios`) |
| Testing           | `@nestjs/testing`, `jest`, `supertest`                           |

> **No Passport, no bcrypt, no ioredis, no third-party OAuth libraries.** Google OAuth 2.0 is implemented via the authorization code flow using direct HTTPS calls to Google's endpoints.

---

## 1.2 OWASP Top 10 Coverage Map

This section defines how to convert OWASP goals into test cases. Each row should drive at least:

1. One happy-path test proving the control works as intended.
2. One abuse-path test proving the control blocks unsafe behavior.
3. One regression test proving the failure mode is explicit, stable, and non-leaky.

| OWASP Risk                                            | Security Objective                                                                                 | Test Design Guide                                                                                                                                    | Minimum Evidence to Assert                                                                 |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **A01:2025 – Broken Access Control**                  | Only explicitly public routes are reachable without authentication                                 | Test that protected endpoints reject missing, invalid, expired, malformed, and wrong-type tokens. Test that `@Public()` routes remain reachable.     | `401/403` on protected routes, success on public routes, no auth bypass via query/body     |
| **A02:2025 – Security Misconfiguration**              | The module starts with safe defaults and fails fast when required security config is missing       | Test startup behavior with missing/invalid env vars, wrong cron expression, missing secrets, disabled headers, and invalid config combinations.      | Bootstrap fails with clear error, safe defaults apply when optional config is omitted      |
| **A03:2025 – Software Supply Chain Failures**         | The module depends only on approved packages and rejects unreviewed security-critical dependencies | Test that approved dependency policy is enforced in review/test gates, and that no forbidden auth stack packages are introduced accidentally.        | Dependency manifest matches approved list, forbidden packages trigger failure              |
| **A04:2025 – Cryptographic Failures**                 | Secrets, passwords, cookies, and JWT contents are handled safely                                   | Test password hashing format and non-reversibility assumptions, secure cookie flags, JWT algorithm enforcement, and absence of sensitive JWT claims. | Password is never returned, cookies are `httpOnly`, payload excludes PII                   |
| **A05:2025 – Injection**                              | Untrusted input cannot alter queries, schemas, or control flow                                     | Test DTO/schema validation with malformed payloads, extra fields, SQL-like strings, script-like input, and type confusion values.                    | Request is rejected before persistence, no extra fields survive validation                 |
| **A06:2025 – Insecure Design**                        | Auth flows fail safely under replay, rotation, lockout, and misuse scenarios                       | Test refresh token rotation, replayed refresh token rejection, expired state rejection, duplicate registration conflicts, and account lockout flows. | Old tokens become unusable, lockout occurs after threshold, generic failures are returned  |
| **A07:2025 – Authentication Failures**                | Login, refresh, logout, and password change flows resist brute force and identity confusion        | Test invalid login loops, lockout duration, refresh token type checks, logout invalidation, password change re-verification, and generic error text. | Same error for bad credentials, lockout enforced, refresh requires refresh token type      |
| **A08:2025 – Software or Data Integrity Failures**    | Tokens and third-party identity data are verified before trust is granted                          | Test JWT signature verification, tampered token rejection, wrong issuer/audience rejection for Google ID tokens, and revoked token denial.           | Modified tokens fail, untrusted Google token fails, revoked entries are enforced           |
| **A09:2025 – Security Logging and Alerting Failures** | Sensitive auth events are observable without leaking secrets                                       | Test that login success, login failure, logout, refresh replay, and OAuth errors emit auditable events without logging raw passwords or tokens.      | Audit/event record exists, secret values are absent from logs                              |
| **A10:2025 – Mishandling of Exceptional Conditions**  | Errors, timeouts, expired state, and invalid token conditions fail safely and consistently         | Test expired OAuth state, malformed JWTs, downstream Google failures, DB exceptions, and cleanup-job failures to ensure safe, generic responses.     | Failures are controlled, secrets are not leaked, and exceptional paths do not grant access |

## 2. Credential Authentication (Username & Password)

### 2.1 Registration

| ID      | Requirement                                                                                                                                                                                                                                |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AUTH-01 | `AuthController` MUST expose `POST /auth/register` accepting a `RegisterDto` (`email`, `username`, `password`).                                                                                                                            |
| AUTH-02 | `AuthService.register()` MUST check for duplicate `email` and `username` via Prisma before proceeding. Conflicts MUST throw `ConflictException`.                                                                                           |
| AUTH-03 | Passwords MUST be hashed using `crypto.scrypt()` with a unique `crypto.randomBytes(16)` salt per user. The stored value MUST be `salt:hash` (hex-encoded). Plain-text passwords MUST never be stored, logged, or included in any response. |
| AUTH-04 | `PasswordService` MUST enforce a configurable `PasswordPolicy`: minimum length (default 10), at least one uppercase letter, one number, and one symbol. Violations MUST throw `BadRequestException` before any DB call.                    |
| AUTH-05 | On success, MUST store in a single transaction `user`, `access_token` and `refresh_token`.                                                                                                                                                 |
| AUTH-06 | On success, `POST /auth/register` MUST return the stored tokens access_token and refresh_token.                                                                                                                                            |

### 2.2 Login

| ID       | Requirement                                                                                                                                                                                                                                                   |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AUTH-07  | `AuthController` MUST expose `POST /auth/login` accepting a `LoginDto` with data (`email`, `password` ) that MUST be validated before proceeding.                                                                                                             |
| AUTH-08  | `AuthService.login()` MUST retrieve the user by email, check lockout status, and perform password verification using `crypto.timingSafeEqual()` to prevent timing attacks.                                                                                    |
| AUTH-09  | On verification failure, `AuthService` MUST increment the `LoginAttempt.failedCount` for the user in PostgreSQL and return a generic `UnauthorizedException("Invalid credentials")` — no indication of whether the email exists _(OWASP A07)_.                |
| AUTH-10  | After `SecurityModuleOptions.lockout.maxAttempts` consecutive failures, the account MUST be locked for `lockout.durationMinutes`. Locked accounts MUST return `UnauthorizedException("Account temporarily locked")` without attempting password verification. |
| AUTH-11  | On successful login, `LoginAttempt.failedCount` MUST be reset to zero and the token pair issued.                                                                                                                                                              |
| AUTH-11A | Repeated `POST /auth/login` requests using the same valid credentials MUST continue to succeed independently, issuing a fresh token pair on each request without locking or rejecting the user solely because the credentials were reused.                    |

### 2.3 Password Management

| ID      | Requirement                                                                                                                    |
| ------- | ------------------------------------------------------------------------------------------------------------------------------ |
| AUTH-12 | `AuthController` MUST expose `PATCH /auth/change-password` accepting `{ currentPassword, newPassword }`.                       |
| AUTH-13 | `AuthService.changePassword()` MUST re-verify `currentPassword` using `crypto.timingSafeEqual()` before applying the new hash. |
| AUTH-14 | On successful password change, ALL active tokens for the user MUST be revoked (full session termination).                      |

---

## 3. Google OAuth 2.0 Authentication

### 3.1 Authorization Code Flow

| ID       | Requirement                                                                                                                                                                                                                                                                                  |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OAUTH-01 | `AuthController` MUST expose `GET /auth/google` that redirects the user to Google's authorization endpoint with scopes `openid email profile`, a `state` parameter (random UUID stored in `OAuthState` table), and `response_type=code`.                                                     |
| OAUTH-02 | `AuthController` MUST expose `GET /auth/google/callback` that receives `code` and `state` from Google. `OAuthService` MUST validate that `state` matches a record in `OAuthState` and that it has not expired (TTL: 10 minutes) before proceeding _(CSRF protection, OWASP A01)_.            |
| OAUTH-03 | `OAuthService` MUST exchange the authorization `code` for tokens by making a server-side `POST` to `https://oauth2.googleapis.com/token` using `@nestjs/axios`. Client credentials (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) MUST come from `ConfigService` _(OWASP A02)_.                |
| OAUTH-04 | `OAuthService` MUST retrieve the user's profile by calling `https://www.googleapis.com/oauth2/v3/userinfo` with the access token obtained in OAUTH-03. Only `sub`, `email`, and `name` fields MUST be consumed.                                                                              |
| OAUTH-05 | Google's ID token returned in the token exchange MUST be verified using Google's public keys fetched from `https://www.googleapis.com/oauth2/v3/certs` via `@nestjs/jwt`. The `aud` claim MUST match `GOOGLE_CLIENT_ID` and `iss` MUST be `accounts.google.com` _(OWASP A08)_.               |
| OAUTH-06 | `OAuthService` MUST implement a **find-or-create** strategy: if an `OAuthAccount` record with the given `sub` exists, link to the existing `User` via `User.oAuthAccount`; otherwise create a new `User` with `passwordHash = null` and create the `OAuthAccount` record.                    |
| OAUTH-07 | A user MUST be able to link a Google account to an existing credential-based account if they are already authenticated (via `POST /auth/google/link` with a valid JWT). `OAuthService` MUST prevent linking an OAuth account already associated with a different user (`ConflictException`). |
| OAUTH-08 | On successful Google login/signup, the same JWT access + refresh token pair flow used for credential login MUST be applied — no separate session mechanism for OAuth users.                                                                                                                  |
| OAUTH-09 | The `OAuthState` record MUST be deleted immediately after validation (single-use). Expired `OAuthState` records MUST be purged by the scheduled cleanup job.                                                                                                                                 |
| OAUTH-10 | Google OAuth client credentials (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL`) MUST be loaded exclusively from `ConfigService` and validated at module startup via a config schema (`ajv`).                                                                             |
| OAUTH-11 | Initially it MUST work with google OAuth server but it have to implement abstract interfaces (entities and services) to agregate other third parties in the future                                                                                                                           |

---

## 4. JWT Token Management & Best Practices

### 4.1 Token Issuance

| ID     | Requirement                                                                                                                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT-01 | `TokenService` MUST issue two tokens on every successful authentication: an **Access Token** (default TTL: 15 min) and a **Refresh Token** (default TTL: 7 days) using `@nestjs/jwt`.                      |
| JWT-02 | The module MUST use **RS256** (asymmetric) signing by default. Private key signs tokens; public key verifies them.                                                                                         |
| JWT-03 | Access Token payload MUST contain only: `sub` (userId), `jti` (UUID v4). **No email, roles, or Personal Information in the payload** _(OWASP A02)_.                                                        |
| JWT-04 | Refresh Token payload MUST contain: `sub`, `jti`,`type: "refresh"`. The `type` claim MUST be checked during refresh to prevent access tokens from being used as refresh tokens _(token confusion attack)_. |
| JWT-05 | All JWT signing keys/secrets MUST be loaded from `ConfigService`.                                                                                                                                          |

### 4.2 Token Validation

| ID     | Requirement                                                                                                                                                                              |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT-06 | `TokenService.verifyAccessToken()` MUST validate: RS256 signature and `exp`. Any failure MUST throw `UnauthorizedException` _(OWASP A08)_.                                               |
| JWT-07 | `JwtAuthGuard` MUST extract the token exclusively from the `access_token` cookie. Tokens in query strings, request bodies, or `Authorization` headers MUST be rejected _(OWASP A01)_.    |
| JWT-08 | `JwtAuthGuard` MUST NOT accept any algorithm other than the configured one. The `algorithms` option in `JwtService.verifyAsync()` MUST be explicitly set _(algorithm confusion attack)_. |

### 4.3 Token Refresh & Rotation

| ID     | Requirement                                                                                                                                                                 |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT-09 | `AuthController` MUST expose `POST /auth/refresh` accepting the refresh token (from `httpOnly` cookie, configurable).                                                       |
| JWT-10 | `TokenService.refreshTokens()` MUST verify the refresh token's signature, expiry, `type: "refresh"` claim, and presence in the `RefreshToken` PostgreSQL table.             |
| JWT-11 | **Refresh token rotation MUST be enforced**: on every valid refresh, the old `RefreshToken` row MUST be revoked and a new token pair issued in a single Prisma transaction. |
| JWT-12 | `RefreshToken` records MUST store: `jti`, `userId`, `expiresAt`, `createdAt`, `replacedByJti` (nullable). `replacedByJti` enables detection of replayed rotated tokens.     |

### 4.4 Token Revocation & Logout

| ID     | Requirement                                                                                                                                                                         |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT-13 | `AuthController` MUST expose `POST /auth/logout` (requires valid JWT) that revokes the current access token (`jti` → `RevokedToken`) and deletes the associated `RefreshToken` row. |
| JWT-14 | A `@Cron` job (via `@nestjs/schedule`) MUST run daily to delete expired rows from `RevokedToken` and `RefreshToken` tables. The purge interval MUST be configurable.                |

### 4.5 Cookie Transport (Optional)

| ID     | Requirement                                                                                                                                                                            |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWT-15 | When `SecurityModuleOptions.cookieTransport = true`, the refresh token MUST be set as an `httpOnly`, `secure`, `sameSite: 'strict'` cookie with `path: '/auth/refresh'` _(OWASP A02)_. |
| JWT-16 | When cookie transport is active, `POST /auth/refresh` MUST read the refresh token from the cookie only, not from the request body.                                                     |
| JWT-17 | When cookie transport is active, `POST /auth/logout` MUST clear the refresh token cookie in addition to revoking tokens.                                                               |

---

## 5. Session Security & OWASP Hardening

### 5.1 Rate Limiting

| ID     | Requirement                                                                                                                                                     |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-01 | `@nestjs/throttler` MUST be applied to `POST /auth/login`, `POST /auth/register`, `POST /auth/refresh` and `GET /auth/google` with TTL and limit _(OWASP A07)_. |

### 5.2 Input Validation

| ID     | Requirement                                                                             |
| ------ | --------------------------------------------------------------------------------------- |
| SEC-02 | All DTOs MUST be validated with `ajv` via a specific ValidationPipe with _(OWASP A03)_. |

### 5.4 Response Hardening

| ID  | Requirement |
| --- | ----------- |

| SEC-03 | Error responses from auth endpoints MUST return generic messages only. Stack traces MUST be suppressed in production via NestJS exception filters. No error message MUST reveal whether an email/username exists _(OWASP A07)_. |

---

## 8. Module Setup & Configuration

| ID     | Requirement                                                                                                                                                              |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CFG-01 | The module MUST expose `SecurityModule.forRoot(options)` and `SecurityModule.forRootAsync({ inject, useFactory, imports })`.                                             |
| CFG-02 | The application MUST register environment-backed config through `ConfigModule.forRoot({ isGlobal: true, envFilePath, load, validate })` before relying on auth features. |
| CFG-03 | `PrismaService` MUST be provided by `PrismaModule`; auth services depend on that provider and MUST NOT instantiate `PrismaClient` directly outside the Prisma wrapper.   |
| CFG-04 | Required env vars MUST be validated at startup via `src/config/env.validation.ts` and fail fast with a descriptive error if missing or invalid.                          |
| CFG-05 | `AuthModule` MUST export `AuthTokenService`, `AUTH_DB`, and `OAUTH_SERVICE` so other modules can depend on abstractions instead of concrete implementations.             |

Current runtime configuration is environment-driven and split into dedicated config factories:

```typescript
// src/config/auth.config.ts
{
  jwtPrivateKey: string; // from JWT_PRIVATE_KEY
  jwtPublicKey: string; // from JWT_PUBLIC_KEY
  jwtDurationMs: number; // from JWT_DURATION
  jwtRefreshDurationMs: number; // from JWT_REFRESH_DURATION
  jwtPurgeCron: string; // from JWT_PURGE_CRON, default '0 0 * * *'
  lockoutMaxAttempts: number; // from LOCKOUT_MAX_ATTEMPTS, default 5
  lockoutDurationMinutes: number; // from LOCKOUT_DURATION_MINUTES, default 15
}

// src/config/oauth.config.ts
{
  googleClientId: string; // from GOOGLE_CLIENT_ID
  googleClientSecret: string; // from GOOGLE_CLIENT_SECRET
  googleCallbackUrl: string; // from GOOGLE_CALLBACK_URL
}

// src/config/password.config.ts
{
  regex: string; // from PASSWORD_REGEX
  errorMessage: string; // from PASSWORD_ERROR_MESSAGE
}
```

`AppModule` is responsible for global bootstrap:

```typescript
@Module({
  imports: [
    AuthModule,
    UserModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      envFilePath: getEnvFilePaths(),
      load: [
        appConfig,
        authConfig,
        databaseConfig,
        oauthConfig,
        passwordConfig,
      ],
      validate,
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 1000,
        limit: 3,
        blockDuration: 10000,
      },
    ]),
  ],
  providers: [
    { provide: APP_GUARD, useClass: JwtGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
```

`AuthModule` owns auth-specific wiring:

```typescript
@Module({
  imports: [
    PrismaModule,
    UserModule,
    HttpModule,
    ScheduleModule.forRoot(),
    ConfigModule.forFeature(authConfig),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule.forFeature(authConfig)],
      inject: [authConfig.KEY],
      useFactory: (config) => ({
        publicKey: config.jwtPublicKey,
        privateKey: config.jwtPrivateKey,
        signOptions: { algorithm: 'RS256' },
      }),
    }),
  ],
  providers: [
    AuthService,
    AuthTokenService,
    AuthPasswordService,
    AuthDBService,
    OAuthGoogleService,
    { provide: AUTH_DB, useClass: AuthDBService },
    { provide: OAUTH_SERVICE, useExisting: OAuthGoogleService },
  ],
  exports: [AuthTokenService, AUTH_DB, OAUTH_SERVICE],
})
export class AuthModule {}
```

---

## 9. Usage Preview

```typescript
// app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    SecurityModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService): SecurityModuleOptions => ({
        jwt: {
          algorithm: 'RS256',
          privateKey: cfg.getOrThrow('JWT_PRIVATE_KEY'),
          publicKey:  cfg.getOrThrow('JWT_PUBLIC_KEY'),
          issuer:     cfg.getOrThrow('JWT_ISSUER'),
          audience:   cfg.getOrThrow('JWT_AUDIENCE'),
          accessTokenTtl:  '15m',
          refreshTokenTtl: '7d',
          resetTokenTtl:   '15m',
        },
        password: {
          scryptKeyLength: 64,
          minLength: 10,
          requireUppercase: true,
          requireNumbers: true,
          requireSymbols: true,
        },
        lockout:   { maxAttempts: 5, durationMinutes: 15 },
        rateLimit: {
          login:          { ttl: 60, limit: 5 },
          register:       { ttl: 60, limit: 3 },
          refresh:        { ttl: 60, limit: 10 },
          forgotPassword: { ttl: 60, limit: 3 },
        },
        google: {
          clientId:       cfg.getOrThrow('GOOGLE_CLIENT_ID'),
          clientSecret:   cfg.getOrThrow('GOOGLE_CLIENT_SECRET'),
          callbackUrl:    cfg.getOrThrow('GOOGLE_CALLBACK_URL'),
          stateTtlMinutes: 10,
        },
        cookieTransport: false,
        cleanupCronExpression: '0 3 * * *',
      }),
    }),
  ],
})
export class AppModule {}

// Protected route example
@Controller('profile')
export class ProfileController {
  @Get()
  // JwtAuthGuard is global — no @UseGuards needed on protected routes
  getProfile(@CurrentUser() user: JwtPayload) {
    return user;
  }

  @Get('public-info')
  @Public()  // explicitly opt out of auth
  getPublicInfo() { ... }
}
```

---

## 10. Out of Scope (v1.0)

- Authorization / RBAC (separate module, planned v2.0)
- MFA / TOTP (planned v2.0)
- Additional OAuth providers (GitHub, Microsoft — planned v2.0)
- Magic link / passwordless login (planned v2.0)
- UI / admin dashboard
- Multi-tenancy
- Cleanup expired database rows
- Env variables error when missing

---

_Document version: 2.0 — March 26 2026_
