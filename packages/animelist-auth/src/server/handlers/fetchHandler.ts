import { MALClient } from "@animelist/client";
import {
  COOKIE_AUTH_CSRF,
  COOKIE_AUTH_CODE_CHALLENGE,
  COOKIE_AUTH_SESSION,
  COOKIE_AUTH_ACCESS_TOKEN,
  generateJwt,
  getServerSession,
} from "../../common/utils";
import { Auth } from "../server";
import { HttpError, error, redirect } from "../../common/httpError";
import type { RequestEvent } from "../../common/types";
import type { HandleAuthOptions, MyAnimeListHandlerOptions } from "./types";
import { CookieJar } from "../../common/cookieJar";
import { getApiUrl } from "../../common/getApiUrl";
import { DEFAULT_SESSION_DURATION_SECONDS, MY_ANIME_LIST_API_URL } from "../../common/constants";

const ALLOWED_FORWARD_HEADERS = ["Authorization", "X-MAL-CLIENT-ID", "Content-Type"];

/**
 * A request handler.
 */
export type Handler = (req: Request) => Promise<Response>;

/**
 * Creates a `Handler` for `MyAnimeList` requests.
 * @param options The options for the handler.
 */
export function createMyAnimeListFetchHandler(options: MyAnimeListHandlerOptions = {}): Handler {
  const { sessionDurationSeconds = DEFAULT_SESSION_DURATION_SECONDS } = options;

  if (sessionDurationSeconds <= 0) {
    throw new Error(`Session duration must be greater than zero but was: ${sessionDurationSeconds}`);
  }

  const apiUrl = getApiUrl();
  const authPath = `${apiUrl}/auth`;

  if (apiUrl.endsWith("/")) {
    throw new Error(`api url cannot end with '/'`);
  }

  return async (request) => {
    const pathname = new URL(request.url).pathname;

    if (!startsWithPathSegment(pathname, apiUrl)) {
      return new Response(null, { status: 404 });
    }

    if (startsWithPathSegment(pathname, authPath)) {
      return handleAuthFetchRequest(request, {
        ...options,
        apiUrl,
        sessionDurationSeconds,
      });
    }

    if (options.callbacks?.onProxyRequest) {
      const next = (request: Request) => proxyFetchRequestToMyAnimeList(apiUrl, request);
      return options.callbacks.onProxyRequest(request, next);
    }

    return proxyFetchRequestToMyAnimeList(apiUrl, request);
  };
}

/**
 * Handle an authentication request.
 * @param request The request event.
 * @param options The authentication options.
 * @returns The response object.
 */
export async function handleAuthFetchRequest(request: Request, options: HandleAuthOptions) {
  const cookies = new CookieJar(request.headers.get("cookie"));
  let response: Response;

  try {
    response = await handleAuth({ request, cookies }, options);
  } catch (err) {
    if (err instanceof HttpError) {
      response = err.toResponse();
    } else {
      throw err;
    }
  }

  // Set the cookies
  for (const cookie of cookies.serialize()) {
    response.headers.append("Set-Cookie", cookie);
  }

  return response;
}

async function handleAuth(event: RequestEvent, options: HandleAuthOptions) {
  const isDev = process.env.NODE_ENV === "development";

  const { apiUrl, sessionDurationSeconds = DEFAULT_SESSION_DURATION_SECONDS, dev = isDev } = options;

  const url = new URL(event.request.url);
  const action = getAuthAction(url.pathname);
  const originUrl = `${url.origin}${apiUrl}/auth`;

  switch (action) {
    case "/sign-in": {
      const redirectTo = `${originUrl}/callback`;
      const { url: authenticationUrl, state, codeChallenge } = await Auth.getAuthenticationUrl({ redirectTo });

      event.cookies.set(COOKIE_AUTH_CSRF, state, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: dev === false,
        maxAge: sessionDurationSeconds,
        domain: options.domain,
      });

      event.cookies.set(COOKIE_AUTH_CODE_CHALLENGE, codeChallenge, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: dev === false,
        maxAge: 60 * 15, // 15min
        domain: options.domain,
      });

      // sign-in callback
      options.callbacks?.onSignIn?.(event);

      throw redirect(307, authenticationUrl);
    }
    case "/sign-out": {
      event.cookies.delete(COOKIE_AUTH_SESSION, { path: "/", domain: options.domain });
      event.cookies.delete(COOKIE_AUTH_CODE_CHALLENGE, { path: "/", domain: options.domain });
      event.cookies.delete(COOKIE_AUTH_ACCESS_TOKEN, { path: "/", domain: options.domain });
      event.cookies.delete(COOKIE_AUTH_CSRF, { path: "/", domain: options.domain });

      // sign-out callback
      options.callbacks?.onSignOut?.(event);

      // Redirect
      throw redirect(307, options.redirectAfterSignInUrl ?? "/");
    }
    case "/callback": {
      const searchParams = url.searchParams;
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const codeChallenge = event.cookies.get(COOKIE_AUTH_CODE_CHALLENGE);

      if (code == null) {
        throw error(401, "No oauth2 code was received");
      }

      if (codeChallenge == null) {
        throw error(401, "No oauth2 code challenge was received");
      }

      const csrf = event.cookies.get(COOKIE_AUTH_CSRF);

      if (state == null || state != csrf) {
        throw error(401, "Invalid auth state");
      }

      const tokens = await Auth.getToken({
        code,
        codeVerifier: codeChallenge,
        redirectTo: `${originUrl}/callback`,
      });

      const userId = Auth.getUserIdFromToken(tokens.access_token);

      if (userId == null) {
        throw error(401, "User id not found");
      }

      const sessionToken = await generateJwt(userId, tokens.refresh_token);

      event.cookies.set(COOKIE_AUTH_SESSION, sessionToken, {
        path: "/",
        httpOnly: true,
        secure: dev === false,
        sameSite: "lax",
        maxAge: sessionDurationSeconds,
        domain: options.domain,
      });

      const { access_token: accessToken, expires_in } = await Auth.refreshToken({ refreshToken: tokens.refresh_token });

      event.cookies.set(COOKIE_AUTH_ACCESS_TOKEN, accessToken, {
        path: "/",
        httpOnly: true,
        secure: dev === false,
        sameSite: "lax",
        maxAge: expires_in,
        domain: options.domain,
      });

      // remove the auth code challenge cookie
      event.cookies.delete(COOKIE_AUTH_CODE_CHALLENGE, { domain: options.domain });

      // auth callback
      options.callbacks?.onCallback?.(event);

      // Redirect
      throw redirect(307, options.redirectAfterSignOutUrl ?? "/");
    }
    case "/token": {
      const { accessToken, expiresAt } = await getMyAnimeListAuthToken(event);

      // token callback
      options.callbacks?.onToken?.(event);

      return json({ accessToken, expiresAt });
    }
    case "/session": {
      const { accessToken, expiresAt } = await getMyAnimeListAuthToken(event);
      const includeStatistics = url.searchParams.get("include_anime_statistics") === "true";

      const malClient = new MALClient({ accessToken });
      const user = await malClient.getMyUserInfo({
        fields: includeStatistics ? ["anime_statistics"] : [],
      });

      event.cookies.set(COOKIE_AUTH_ACCESS_TOKEN, accessToken, {
        path: "/",
        maxAge: sessionDurationSeconds,
        httpOnly: true,
        sameSite: "strict",
        domain: options.domain,
      });

      // session callback
      options.callbacks?.onSession?.({ user, accessToken, expiresAt }, event);

      return json({
        user,
        accessToken,
        expiresAt,
      });
    }
    default: {
      console.error(`❌ Invalid auth action: ${action}`);
      throw error(404);
    }
  }
}

async function getMyAnimeListAuthToken(event: RequestEvent) {
  const token = event.cookies.get(COOKIE_AUTH_SESSION);

  if (token == null) {
    throw error(401);
  }

  const authenticated = await getServerSession(event.cookies);

  if (authenticated == null) {
    throw error(401);
  }

  const { refreshToken, userId } = authenticated;
  const { access_token: accessToken, expires_in } = await Auth.refreshToken({
    refreshToken,
  });

  // OAuth2 `expires_in` is in seconds
  // https://www.rfc-editor.org/rfc/rfc6749#section-5.1
  const accessTokenExpiresMs = expires_in * 1000;

  // Keep in mind some delay could exists in the time, so we should consider the token
  // will expire before the actual expiration date.
  const expiresAt = new Date(accessTokenExpiresMs + Date.now());

  return { accessToken, expiresAt, userId };
}

function getAuthAction(pathname: string) {
  const lastSegment = pathname.lastIndexOf("/");
  return lastSegment < 0 ? pathname : pathname.slice(lastSegment);
}

/**
 * Forwards a request to `MyAnimeList`.
 * @param apiUrl The path to the current API endpoint. `/api/myanimelist`
 * @param request The current request event.
 */
export async function proxyFetchRequestToMyAnimeList(apiUrl: string, request: Request) {
  const forwardHeaders: Record<string, string> = {};

  for (const [key, value] of request.headers.entries()) {
    if (ALLOWED_FORWARD_HEADERS.some((x) => x.toLowerCase() === key.toLowerCase())) {
      forwardHeaders[key] = value;
    }
  }

  const url = new URL(request.url);
  const path = url.pathname.slice(apiUrl.length);
  const search = url.search;
  const myAnimeListApiUrl = `${MY_ANIME_LIST_API_URL}${path}${search}`;

  if (process.env.NODE_ENV !== "production" && process.env.MAL_REQUEST_DEBUG) {
    // 🍥 GET: https://api.myanimelist.net/v2/anime/suggestions
    console.log(`🍥 ${request.method}: ${myAnimeListApiUrl}`);
  }

  const res = await fetch(myAnimeListApiUrl, {
    method: request.method,
    body: request.body,
    headers: forwardHeaders,
    signal: request.signal,
    cache: request.cache,
    credentials: request.credentials,
    integrity: request.integrity,
    keepalive: request.keepalive,
    mode: request.mode,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,

    // @ts-expect-error This property is required to send a body
    // https://github.com/nodejs/node/issues/46221#issuecomment-1482439958
    duplex: "half",
  });

  if (!res.ok) {
    // ❌ GET (404) Not Found: https://api.example.com/users
    console.error(`❌ ${request.method} (${res.status}) ${res.statusText}: ${myAnimeListApiUrl}`);
  }

  return res;
}

function json(data: unknown) {
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function startsWithPathSegment(pathname: string, other: string) {
  const a = pathname.split("/").filter((x) => x.length > 0);
  const b = other.split("/").filter((x) => x.length > 0);

  if (a.length < b.length) {
    return false;
  }

  for (let i = 0; i < b.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }

  return true;
}
