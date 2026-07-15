import { Show, createSignal } from "solid-js";
import { render } from "solid-js/web";
import "./styles.css";

type LoginData = {
  requestId: string;
  client: string;
  csrf: string;
  username: string;
  error: string;
};

function readLoginData(root: HTMLDivElement): LoginData {
  return {
    requestId: root.dataset.requestId ?? "",
    client: root.dataset.client ?? "",
    csrf: root.dataset.csrf ?? "",
    username: root.dataset.username ?? "",
    error: root.dataset.error ?? "",
  };
}

function LoginCard(props: LoginData) {
  const hasError = () => props.error.trim().length > 0;
  const [submitting, setSubmitting] = createSignal(false);

  return (
    <main class="login-shell">
      <section class="card" aria-labelledby="login-title">
        <header class="card-header">
          <div class="identity" aria-label="Hoocloak">
            <span class="identity-mark" aria-hidden="true">H</span>
            <span class="brand">Hoocloak</span>
          </div>
          <p class="eyebrow">Development identity</p>
          <h1 id="login-title">Sign in</h1>
          <p class="client">
            Continue to <strong>{props.client}</strong>
          </p>
        </header>

        <Show when={hasError()}>
          <div class="alert" id="sign-in-error" role="alert" aria-live="assertive">
            Sign-in failed. Check your username and password and try again.
          </div>
        </Show>

        <form method="post" action="/login" aria-busy={submitting()} onSubmit={() => setSubmitting(true)}>
          <input type="hidden" name="authRequestID" value={props.requestId} />
          <input type="hidden" name="csrf" value={props.csrf} />

          <div class="field">
            <label for="username">Username</label>
            <input
              id="username"
              name="username"
              value={props.username}
              autocomplete="username"
              autofocus
              required
              aria-invalid={hasError() ? "true" : undefined}
              aria-describedby={hasError() ? "sign-in-error" : undefined}
            />
          </div>

          <div class="field">
            <label for="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autocomplete="current-password"
              required
              aria-invalid={hasError() ? "true" : undefined}
              aria-describedby={hasError() ? "sign-in-error" : undefined}
            />
          </div>

          <button type="submit" disabled={submitting()}>
            {submitting() ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p class="notice">
          <span aria-hidden="true">Dev</span>
          For local development only.
        </p>
      </section>
    </main>
  );
}

const root = document.getElementById("login-root");

if (!(root instanceof HTMLDivElement)) {
  throw new Error("Login root was not found");
}

render(() => <LoginCard {...readLoginData(root)} />, root);
