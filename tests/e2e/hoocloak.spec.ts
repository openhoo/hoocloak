import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "./fixtures";

const app =
  process.env.E2E_SPA_ORIGIN ??
  `http://localhost:${process.env.E2E_SPA_PORT ?? "13000"}`;
const provider =
  process.env.E2E_PROVIDER_ORIGIN ??
  `http://hoocloak.localhost:${process.env.E2E_PROVIDER_PORT ?? "18080"}`;
const issuer = `${provider}/realms/development`;
const partnerIssuer = `${provider}/realms/partner`;
const api =
  process.env.E2E_API_ORIGIN ??
  `http://api.localhost:${process.env.E2E_API_PORT ?? "15099"}`;

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

async function serviceAccessToken(
  request: APIRequestContext,
  tokenIssuer: string,
  clientId: string,
  secret: string,
  scope: string,
) {
  const tokenResponse = await request.post(`${tokenIssuer}/oauth/token`, {
    form: { grant_type: "client_credentials", scope },
    headers: {
      Authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`,
    },
  });
  expect(tokenResponse.ok()).toBeTruthy();
  return (await tokenResponse.json()) as {
    access_token: string;
    expires_in: number;
    scope: string;
    token_type: string;
  };
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

test("Alice can authenticate, renew, access APIs, then logout revokes provider state but not the unexpired self-contained JWT", async ({
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

  const activeToken = await request.get(`${issuer}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expect(activeToken.ok()).toBeTruthy();

  // oidc-client-ts normally revokes tokens before redirecting to end_session. Stub
  // those browser requests so only the provider's TerminateSession can invalidate
  // this still-active access-token family.
  const clientRevocationAttempts: string[] = [];
  await page.route(`${issuer}/revoke`, async (route) => {
    const body = new URLSearchParams(route.request().postData() ?? "");
    const token = body.get("token");
    if (token !== null) {
      clientRevocationAttempts.push(token);
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(`${app}/`);
  await expect(
    page.getByRole("heading", { name: "No development identity is active" }),
  ).toBeVisible();
  expect(clientRevocationAttempts).toContain(accessToken);

  const revokedToken = await request.get(`${issuer}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expect(revokedToken.status()).toBe(401);

  // Resource servers validate the signed JWT locally; provider-side revocation is not introspected.
  const locallyValidatedToken = await request.get(`${api}/api/profile`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  expect(locallyValidatedToken.ok()).toBeTruthy();
  expect(await locallyValidatedToken.json()).toMatchObject({
    sub: "alice",
    name: "Alice Admin",
  });
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

test("resource server rejects cross-realm tokens and the wrong hoocloak-api audience", async ({
  request,
}) => {
  const token = await serviceAccessToken(
    request,
    issuer,
    "example-worker",
    "dev-secret",
    "api.read",
  );
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

  const partnerToken = await serviceAccessToken(
    request,
    partnerIssuer,
    "example-worker",
    "partner-secret",
    "partner.read",
  );
  // The audience is valid for this API, so this proves cross-realm issuer/signing-key isolation.
  const partnerProfile = await request.get(`${api}/api/profile`, {
    headers: { Authorization: `Bearer ${partnerToken.access_token}` },
  });
  expect(partnerProfile.status()).toBe(401);

  const wrongAudienceToken = await serviceAccessToken(
    request,
    issuer,
    "wrong-audience-worker",
    "dev-secret",
    "api.read",
  );
  // The issuer is valid for this API, so this rejection specifically defends audience isolation.
  const wrongAudienceProfile = await request.get(`${api}/api/profile`, {
    headers: { Authorization: `Bearer ${wrongAudienceToken.access_token}` },
  });
  expect(wrongAudienceProfile.status()).toBe(401);
});
