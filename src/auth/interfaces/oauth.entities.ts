import { AuthTokens } from './auth.entities';

export interface OAuthRedirect {
  url: string;
}

export interface OAuthCallbackArgs {
  code: string;
  state: string;
}

export type OAuthCallbackResult = AuthTokens;
