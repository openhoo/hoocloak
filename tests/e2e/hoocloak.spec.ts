import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

const app = "http://localhost:13000";
const provider = "http://hoocloak.localhost:18080";
const issuer = `${provider}/realms/development`;
const api = "http://api.localhost:15099";

async function signIn(page: Page, username: string, password: string) {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "No development identity is active" }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Sign in with Hoocloak" }).click();
  await expect(page).toHaveURL(new RegExp(`^${issuer}/login\\?`));
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Continue to react-spa")).toBeVisible();

  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await expect(page).toHaveURL(`${app}/`);
}

function endpoint(page: Page, path: "/api/profile" | "/api/admin") {
  return page.locator("article.endpoint").filter({ hasText: path });
}

async function callEndpoint(
  page: Page,
  path: "/api/profile" | "/api/admin",
  status: number,
) {
  const card = endpoint(page, path);
  await card.getByRole("button", { name: "Call endpoint" }).click();
  await expect(card.locator(".response > strong")).toHaveText(String(status));
  return card.locator("pre");
}

test("public stack, security headers, discovery, and unauthenticated API are healthy", async ({
  page,
  request,
  browserMonitor: _browserMonitor,
}) => {
  const landing = await page.goto("/");
  expect(landing?.status()).toBe(200);
  expect(landing?.headers()["content-security-policy"]).toContain("default-src 'self'");
  expect(landing?.headers()["x-content-type-options"]).toBe("nosniff");
  expect(landing?.headers()["x-frame-options"]).toBe("DENY");
  await expect(
    page.getByRole("heading", { name: "See the whole authentication boundary." }),
  ).toBeVisible();

  const ready = await request.get(`${provider}/ready`);
  expect(ready.ok()).toBeTruthy();
  expect(await ready.json()).toMatchObject({ status: "ok" });

  const health = await request.get(`${provider}/healthz`);
  expect(health.ok()).toBeTruthy();
  expect(await health.json()).toEqual({ status: "ok" });

  const discovery = await request.get(`${issuer}/.well-known/openid-configuration`);
  expect(discovery.ok()).toBeTruthy();
  expect(await discovery.json()).toMatchObject({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/keys`,
    code_challenge_methods_supported: ["S256"],
  });

  const publicApi = await request.get(`${api}/api/public`);
  expect(publicApi.ok()).toBeTruthy();
  expect(await publicApi.json()).toEqual({
    message: "Hoocloak API is running.",
  });

  const protectedApi = await request.get(`${api}/api/profile`);
  expect(protectedApi.status()).toBe(401);
});

test("invalid password is rejected without losing entered username", async ({
  page,
  browserMonitor,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with Hoocloak" }).click();
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill("not-the-password");
  browserMonitor.expectHttpError(401, `${issuer}/login`);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await expect(page).toHaveURL(`${issuer}/login`);
  await expect(page.getByRole("alert")).toHaveText("Invalid username or password.");
  await expect(page.getByLabel("Username")).toHaveValue("alice");
  await expect(page.getByLabel("Username")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByLabel("Password")).toHaveAttribute("aria-invalid", "true");
});

test("Alice can authenticate, renew, access profile and admin, then sign out", async ({
  page,
  request,
  browserMonitor: _browserMonitor,
}) => {
  await signIn(page, "alice", "alice-password");
  await expect(page.getByLabel("Current session")).toContainText("Alice Admin");

  const claims = page.locator(".claims-panel pre");
  await expect(claims).toContainText('"preferred_username": "alice"');
  await expect(claims).toContainText('"admin"');
  await expect(claims).toContainText('"api.read"');
  const originalClaims = JSON.parse(await claims.innerText()) as { jti: string };

  const profile = await callEndpoint(page, "/api/profile", 200);
  await expect(profile).toContainText('"name": "Alice Admin"');
  await expect(profile).toContainText('"admin"');
  await expect(profile).toContainText('"api.read"');

  const admin = await callEndpoint(page, "/api/admin", 200);
  await expect(admin).toContainText('"message": "Admin access granted."');

  await page.getByRole("button", { name: "Renew token" }).click();
  await expect(page.getByRole("button", { name: "Renew token" })).toBeEnabled();
  await expect
    .poll(async () => (JSON.parse(await claims.innerText()) as { jti: string }).jti)
    .not.toBe(originalClaims.jti);

  const accessToken = await page.evaluate(() => {
    for (const value of Object.values(sessionStorage)) {
      try {
        const candidate = JSON.parse(value) as { access_token?: unknown };
        if (typeof candidate.access_token === "string") {
          return candidate.access_token;
        }
      } catch {
        // Ignore non-JSON application state.
      }
    }
    throw new Error("OIDC access token was not found in session storage");
  });

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(`${app}/`);
  await expect(
    page.getByRole("heading", { name: "No development identity is active" }),
  ).toBeVisible();

  const revokedToken = await request.get(`${issuer}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expect(revokedToken.status()).toBe(401);
});

test("Bob can access profile but is forbidden from admin", async ({
  page,
  browserMonitor,
}) => {
  await signIn(page, "bob", "bob-password");
  await expect(page.getByLabel("Current session")).toContainText("Bob Reader");

  const profile = await callEndpoint(page, "/api/profile", 200);
  await expect(profile).toContainText('"name": "Bob Reader"');
  await expect(profile).toContainText('"reader"');

  browserMonitor.expectHttpError(403, `${api}/api/admin`);
  const admin = await callEndpoint(page, "/api/admin", 403);
  await expect(admin).not.toContainText("Admin access granted.");
});

test("service account receives a scoped token accepted by resource server", async ({
  request,
}) => {
  const tokenResponse = await request.post(`${issuer}/oauth/token`, {
    form: {
      grant_type: "client_credentials",
      scope: "api.read",
    },
    headers: {
      Authorization: `Basic ${Buffer.from("example-worker:dev-secret").toString("base64")}`,
    },
  });
  expect(tokenResponse.ok()).toBeTruthy();
  const token = (await tokenResponse.json()) as {
    access_token: string;
    expires_in: number;
    scope: string;
    token_type: string;
  };
  expect(token).toMatchObject({
    scope: "api.read",
    token_type: "Bearer",
  });
  expect(token.expires_in).toBeGreaterThanOrEqual(295);
  expect(token.expires_in).toBeLessThanOrEqual(300);
  expect(token.access_token.split(".")).toHaveLength(3);

  const profile = await request.get(`${api}/api/profile`, {
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  expect(profile.ok()).toBeTruthy();
  expect(await profile.json()).toMatchObject({
    roles: ["worker"],
    permissions: ["api.read"],
  });

  const admin = await request.get(`${api}/api/admin`, {
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  expect(admin.status()).toBe(403);
});
