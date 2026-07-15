import type { AuthProviderProps } from "react-oidc-context";
import {
  WebStorageStateStore,
  type SignoutResponse,
  type User,
} from "oidc-client-ts";

function readOrigin(name: string, value: string | undefined): URL {
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL.`);
  }

  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error(`${name} must be an absolute HTTP(S) origin without credentials, a path, query, or fragment.`);
  }
  if (url.protocol === "http:" && !isLocalHost(url.hostname)) {
    throw new Error(`${name} must use HTTPS unless it targets loopback, localhost, or a .localhost host.`);
  }

  return url;
}

function isLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  const octets = host.split(".");
  return octets.length === 4 && octets[0] === "127" && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

const authority = readOrigin("VITE_OIDC_AUTHORITY", import.meta.env.VITE_OIDC_AUTHORITY);
export const apiBase = readOrigin("VITE_API_BASE_URL", import.meta.env.VITE_API_BASE_URL);

export function safeReturnTo(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\")
  ) {
    return "/";
  }

  const resolved = new URL(value, window.location.origin);
  return resolved.origin === window.location.origin ? `${resolved.pathname}${resolved.search}${resolved.hash}` : "/";
}

function stateReturnTo(state: unknown): string {
  if (typeof state !== "object" || state === null || !("returnTo" in state)) {
    return "/";
  }
  return safeReturnTo(state.returnTo);
}

function onSigninCallback(user: User | undefined): void {
  window.history.replaceState({}, document.title, stateReturnTo(user?.state));
}

function onSignoutCallback(response: SignoutResponse | undefined): void {
  window.history.replaceState({}, document.title, stateReturnTo(response?.state));
}

const origin = window.location.origin;

export const authConfig: AuthProviderProps = {
  authority: authority.toString(),
  client_id: "react-spa",
  redirect_uri: `${origin}/auth/callback`,
  post_logout_redirect_uri: `${origin}/auth/logout/callback`,
  response_type: "code",
  scope: "openid profile email offline_access api.read",
  disablePKCE: false,
  automaticSilentRenew: true,
  monitorSession: false,
  revokeTokensOnSignout: true,
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  onSigninCallback,
  matchSignoutCallback: () => window.location.pathname === "/auth/logout/callback",
  onSignoutCallback,
};
