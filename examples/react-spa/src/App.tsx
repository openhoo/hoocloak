import { useEffect, useRef, useState } from "react";
import { useAuth } from "react-oidc-context";
import { apiBase, safeReturnTo } from "./auth";

type ApiResult = {
  status: number | "Network error";
  body: unknown;
};

type Endpoint = "/api/profile" | "/api/admin";

function decodeDebugClaims(token: string | undefined): unknown {
  if (!token) return null;

  try {
    const payload = token.split(".")[1];
    if (!payload) throw new Error("JWT payload is missing.");
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const bytes = Uint8Array.from(window.atob(padded), (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    return { error: "The access-token payload could not be decoded for display." };
  }
}


export default function App() {
  const auth = useAuth();
  const [silentRenewNeedsLogin, setSilentRenewNeedsLogin] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [results, setResults] = useState<Partial<Record<Endpoint, ApiResult>>>({});
  const removedStaleUser = useRef(false);

  useEffect(() => {
    const onSilentRenewError = (error: Error) => {
      const errorCode = "error" in error && typeof error.error === "string" ? error.error : "";
      if (errorCode !== "login_required" && !error.message.includes("login_required")) return;

      auth.stopSilentRenew();
      setSilentRenewNeedsLogin(true);
      if (!removedStaleUser.current) {
        removedStaleUser.current = true;
        void auth.removeUser().catch(() => {
          setActionError("The expired local session could not be cleared. Reload and sign in again.");
        });
      }
    };

    auth.events.addSilentRenewError(onSilentRenewError);
    return () => auth.events.removeSilentRenewError(onSilentRenewError);
  }, [auth]);

  async function signIn() {
    setActionError(null);
    setPendingAction("signin");
    try {
      await auth.signinRedirect({
        state: {
          returnTo:
            window.location.pathname === "/auth/callback" ||
            window.location.pathname === "/auth/logout/callback"
              ? "/"
              : safeReturnTo(
                  `${window.location.pathname}${window.location.search}${window.location.hash}`,
                ),
        },
      });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Sign-in could not be started.");
      setPendingAction(null);
    }
  }

  async function signOut() {
    setActionError(null);
    setPendingAction("signout");
    try {
      await auth.signoutRedirect({ state: { returnTo: "/" } });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Sign-out could not be started.");
      setPendingAction(null);
    }
  }

  async function renewSession() {
    setActionError(null);
    setPendingAction("renew");
    try {
      await auth.signinSilent();
      setSilentRenewNeedsLogin(false);
      removedStaleUser.current = false;
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The session could not be renewed.");
    } finally {
      setPendingAction(null);
    }
  }

  async function callApi(endpoint: Endpoint) {
    if (!auth.user?.access_token) return;

    setActionError(null);
    setPendingAction(endpoint);
    try {
      const response = await fetch(new URL(endpoint, apiBase), {
        headers: { Authorization: `Bearer ${auth.user.access_token}` },
        credentials: "omit",
      });
      const text = await response.text();
      let body: unknown = null;
      if (text) {
        try {
          body = JSON.parse(text) as unknown;
        } catch {
          body = text;
        }
      }
      setResults((current) => ({ ...current, [endpoint]: { status: response.status, body } }));
    } catch (error) {
      setResults((current) => ({
        ...current,
        [endpoint]: {
          status: "Network error",
          body: { error: error instanceof Error ? error.message : "The API could not be reached." },
        },
      }));
    } finally {
      setPendingAction(null);
    }
  }

  const debugClaims = decodeDebugClaims(auth.user?.access_token);
  const callbackInProgress = auth.isLoading || auth.activeNavigator !== undefined;

  return (
    <main className="shell">
      <header className="masthead">
        <a className="wordmark" href="/" aria-label="Hoocloak home">
          Hoocloak
        </a>
        <span className="environment">Development identity</span>
      </header>

      <section className="intro" aria-labelledby="page-title">
        <p className="eyebrow">OIDC integration console</p>
        <h1 id="page-title">See the whole authentication boundary.</h1>
        <p className="lede">
          Sign in through the provider, inspect the untrusted browser view of the token, and ask the API to make the real authorization decision.
        </p>
      </section>

      {callbackInProgress ? (
        <section className="status-panel" aria-live="polite" aria-busy="true">
          <span className="status-mark" aria-hidden="true" />
          <div>
            <h2>Completing the identity exchange</h2>
            <p>The callback is being verified and the tab session is being restored.</p>
          </div>
        </section>
      ) : auth.error ? (
        <section className="status-panel status-panel--error" role="alert">
          <div>
            <h2>Authentication did not complete</h2>
            <p>{auth.error.message}</p>
            <button className="button button--primary" type="button" onClick={() => void signIn()}>
              Start a new sign-in
            </button>
          </div>
        </section>
      ) : !auth.isAuthenticated ? (
        <section className="signin-panel" aria-labelledby="signin-title">
          <div>
            <p className="section-label">Tab session</p>
            <h2 id="signin-title">No development identity is active</h2>
            <p>
              Sign in to receive a short-lived access token. Credentials are entered only on the Hoocloak provider page.
            </p>
          </div>
          <button
            className="button button--primary"
            type="button"
            onClick={() => void signIn()}
            disabled={pendingAction === "signin"}
          >
            {pendingAction === "signin" ? "Opening Hoocloak…" : silentRenewNeedsLogin ? "Sign in again" : "Sign in with Hoocloak"}
          </button>
        </section>
      ) : (
        <>
          <section className="session-strip" aria-label="Current session">
            <div>
              <span className="section-label">Signed in as</span>
              <strong>{auth.user?.profile.name ?? auth.user?.profile.preferred_username ?? auth.user?.profile.sub}</strong>
            </div>
            <div className="session-actions">
              <button
                className="button button--quiet"
                type="button"
                onClick={() => void renewSession()}
                disabled={pendingAction !== null}
              >
                {pendingAction === "renew" ? "Renewing…" : "Renew token"}
              </button>
              <button
                className="button button--secondary"
                type="button"
                onClick={() => void signOut()}
                disabled={pendingAction !== null}
              >
                {pendingAction === "signout" ? "Signing out…" : "Sign out"}
              </button>
            </div>
          </section>

          <div className="workspace">
            <section className="api-panel" aria-labelledby="api-title">
              <div className="panel-heading">
                <div>
                  <p className="section-label">Resource server</p>
                  <h2 id="api-title">Ask the API</h2>
                </div>
                <p>The bearer access token is sent directly. No cookies, proxy, or ID token are used.</p>
              </div>

              {(["/api/profile", "/api/admin"] as const).map((endpoint) => {
                const result = results[endpoint];
                const label = endpoint === "/api/profile" ? "Profile policy" : "Admin policy";
                return (
                  <article className="endpoint" key={endpoint}>
                    <div className="endpoint-line">
                      <div>
                        <span className="method">GET</span>
                        <code>{endpoint}</code>
                        <h3>{label}</h3>
                      </div>
                      <button
                        className="button button--secondary"
                        type="button"
                        onClick={() => void callApi(endpoint)}
                        disabled={pendingAction !== null}
                      >
                        {pendingAction === endpoint ? "Calling…" : "Call endpoint"}
                      </button>
                    </div>
                    <div className="response" aria-live="polite">
                      <span className="response-label">HTTP status</span>
                      <strong>{result?.status ?? "Not called"}</strong>
                      <pre>{result ? JSON.stringify(result.body, null, 2) : "Response JSON will appear here."}</pre>
                    </div>
                  </article>
                );
              })}
            </section>

            <aside className="claims-panel" aria-labelledby="claims-title">
              <p className="section-label">Browser inspection</p>
              <h2 id="claims-title">Debug claims; validation happens in the API.</h2>
              <p>This payload is decoded for visibility only. It is not proof of identity or permission.</p>
              <pre>{JSON.stringify(debugClaims, null, 2)}</pre>
            </aside>
          </div>
        </>
      )}

      {actionError && (
        <div className="action-error" role="alert">
          <strong>Action failed</strong>
          <span>{actionError}</span>
        </div>
      )}

      <footer>
        <span>Public client · Authorization Code + PKCE</span>
        <span>State is stored in this tab only</span>
      </footer>
    </main>
  );
}
