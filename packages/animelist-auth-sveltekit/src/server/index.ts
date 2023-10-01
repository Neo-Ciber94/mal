import { DEFAULT_SESSION_DURATION_SECONDS, handleAuthFetchRequest, proxyFetchRequestToMyAnimeList } from "@animelist/auth/server";
import { type MyAnimeListHandlerOptions } from "@animelist/auth/server/handlers";
import { type Handle } from "@sveltejs/kit";
import { getApiUrl } from "@animelist/auth/common";

/**
 * Creates a sveltekit `Handler` for `MyAnimeList` requests.
 * @param options The options for the handler.
 */
export function createMyAnimeListHandler(options: MyAnimeListHandlerOptions = {}): Handle {
    const { sessionDurationSeconds = DEFAULT_SESSION_DURATION_SECONDS } = options;

    if (sessionDurationSeconds <= 0) {
        throw new Error(`Session duration must be greater than zero but was: ${sessionDurationSeconds}`);
    }

    const apiUrl = getApiUrl();
    const authPath = `${apiUrl}/auth`;

    if (apiUrl.endsWith("/")) {
        throw new Error(`api url cannot end with '/'`);
    }

    return async ({ event, resolve }) => {
        const pathname = event.url.pathname;

        if (!startsWithPathSegment(pathname, apiUrl)) {
            return resolve(event);
        }

        if (startsWithPathSegment(pathname, authPath)) {
            return handleAuthFetchRequest(event.request, {
                ...options,
                apiUrl,
                sessionDurationSeconds,
            });
        }

        if (options.callbacks?.onProxyRequest) {
            const next = (request: Request) => proxyFetchRequestToMyAnimeList(apiUrl, request);
            return options.callbacks.onProxyRequest(event.request, next);
        }

        return proxyFetchRequestToMyAnimeList(apiUrl, event.request);
    }
}

function startsWithPathSegment(pathname: string, other: string) {
    const a = pathname.split("/").filter(x => x.length > 0);
    const b = other.split("/").filter(x => x.length > 0);

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