import type { User } from "@animelist/core";
import type { RequestEvent } from "../../common/types";

export type OnSessionData = {
  /**
   * The `MyAnimeList` user.
   */
  user: User;

  /**
   * The `MyAnimeList` access token of the user.
   */
  accessToken: string;

  /**
   * Expiration date of the session.
   */
  expiresAt: Date;
};

/**
 * Auth callbacks.
 */
export type AuthCallbacks = {
  /**
   * Called after sign-in.
   */
  onSignIn?: (event: RequestEvent) => void;

  /**
   * Called after sign-out.
   */
  onSignOut?: (event: RequestEvent) => void;

  /**
   * Called after the auth callback.
   */
  onCallback?: (event: RequestEvent) => void;

  /**
   * Called after generating a session token.
   */
  onToken?: (event: RequestEvent) => void;

  /**
   * Called after generating an user session.
   */
  onSession?: (session: OnSessionData, event: RequestEvent) => void;

  /**
   * Called before a proxy request.
   * @param event The current request.
   * @param next The proxy request.
   * @returns The response of the request.
   */
  onProxyRequest?: (request: Request, next: (event: Request) => Promise<Response>) => Promise<Response>;
};

/**
 * Options for the auth handler.
 */
export interface MyAnimeListHandlerOptions {
  /**
   * Duration per session, defaults to 7 days.
   */
  sessionDurationSeconds?: number;

  /**
   * Url to redirect after sign-in.
   */
  redirectAfterSignInUrl?: string;

  /**
   * Url to redirect after sign-out.
   */
  redirectAfterSignOutUrl?: string;

  /**
   * Callbacks.
   */
  callbacks?: AuthCallbacks;

  /**
   * Set the domain for the session cookie.
   */
  domain?: string;
}

export type HandleAuthOptions = MyAnimeListHandlerOptions & {
  /**
   * The base path for the api.
   *
   * @example `/api/myanimelist`
   */
  apiUrl: string;

  /**
   * Duration of a session.
   */
  sessionDurationSeconds?: number;

  /**
   * If the app is running in development mode.
   */
  dev?: boolean;
};
