import { OAuthCallbackArgs, OAuthCallbackResult, OAuthRedirect } from './oauth.entities';

export const OAUTH_SERVICE = Symbol('OAUTH_SERVICE');

export interface OAuthServiceI {
  createAuthRedirectUrl(): Promise<OAuthRedirect>;
  handleCallback(args: OAuthCallbackArgs): Promise<OAuthCallbackResult>;
}
