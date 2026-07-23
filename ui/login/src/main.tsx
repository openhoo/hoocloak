import { Show } from "solid-js";
import { render } from "solid-js/web";
import "./styles.css";

type LoginIdentity = {
  ID: string;
  Username: string;
  Name: string;
  Email: string;
};

type LoginData = {
  basePath: string;
  requestId: string;
  client: string;
  csrf: string;
  mode: "password" | "select";
  username: string;
  selectedId: string;
  identities: LoginIdentity[];
  error: string;
};

function readLoginData(root: HTMLDivElement): LoginData {
  const basePath = root.dataset.basePath ?? "";
  if (!/^\/realms\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(basePath)) {
    throw new Error("Invalid realm base path");
  }
  const identities = JSON.parse(root.dataset.identities ?? "[]") as LoginIdentity[];
  return {
    basePath,
    requestId: root.dataset.requestId ?? "",
    client: root.dataset.client ?? "",
    csrf: root.dataset.csrf ?? "",
    mode: root.dataset.mode === "select" ? "select" : "password",
    username: root.dataset.username ?? "",
    selectedId: root.dataset.selectedId ?? "",
    identities,
    error: root.dataset.error ?? "",
  };
}

function LoginCard(props: LoginData) {
  const hasError = () => props.error.trim().length > 0;

  return (
    <main class="login-shell">
      <section class="card" aria-labelledby="login-title">
        <header class="card-header">
          <div class="identity" aria-label="Hoocloak">
            <span class="identity-mark" aria-hidden="true">H</span>
            <span class="brand">Hoocloak</span>
          </div>
          <p class="eyebrow">Development identity</p>
          <h1 id="login-title">{props.mode === "select" ? "Choose an identity" : "Sign in"}</h1>
          <p class="client">
            Continue to <strong>{props.client}</strong>
          </p>
        </header>

        <Show when={hasError()}>
          <div class="alert" id="sign-in-error" role="alert" aria-live="assertive">
            {props.error}
          </div>
        </Show>

        <form method="post" action={`${props.basePath}/login`}>
          <input type="hidden" name="authRequestID" value={props.requestId} />
          <input type="hidden" name="csrf" value={props.csrf} />

          <Show
            when={props.mode === "select"}
            fallback={
              <>
                <div class="field">
                  <label for="username">Username</label>
                  <input id="username" name="username" value={props.username} autocomplete="username" autofocus required aria-invalid={hasError() ? "true" : undefined} aria-describedby={hasError() ? "sign-in-error" : undefined} />
                </div>
                <div class="field">
                  <label for="password">Password</label>
                  <input id="password" name="password" type="password" autocomplete="current-password" required aria-invalid={hasError() ? "true" : undefined} aria-describedby={hasError() ? "sign-in-error" : undefined} />
                </div>
              </>
            }
          >
            <fieldset class="identity-list" aria-describedby={hasError() ? "sign-in-error" : undefined}>
              <legend>Select the user you want to act as</legend>
              {props.identities.map((identity, index) => (
                <label class="identity-option">
                  <input type="radio" name="identity" value={identity.ID} checked={identity.ID === props.selectedId} required={index === 0} autofocus={index === 0} />
                  <span>
                    <strong>{identity.Name || identity.Username}</strong>
                    <small>@{identity.Username}{identity.Email ? ` · ${identity.Email}` : ""}</small>
                  </span>
                </label>
              ))}
            </fieldset>
          </Show>

          <button type="submit">
            {props.mode === "select" ? "Continue as selected user" : "Sign in"}
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
