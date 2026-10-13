import { apiOrigin, appOrigin, expect, test } from "./fixtures";

test("development identity selection completes login and logout", async ({
  page,
  browserMonitor: _browserMonitor,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with Hoocloak" }).click();

  await expect(page.getByRole("heading", { name: "Choose an identity" })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Alice Admin/ })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Bob Reader/ })).toBeVisible();

  await page.getByRole("radio", { name: /Alice Admin/ }).check();
  await page.getByRole("button", { name: "Continue as selected user" }).click();

  await expect(page).toHaveURL(`${appOrigin}/`);
  await expect(page.getByLabel("Current session")).toContainText("Alice Admin");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(`${appOrigin}/`);
  await expect(
    page.getByRole("heading", { name: "No development identity is active" }),
  ).toBeVisible();
});

test("mobile identity selection supports the keyboard and retains reader authorization", async ({
  page,
  browserName,
  browserMonitor,
}, testInfo) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with Hoocloak" }).click();
  const alice = page.getByRole("radio", { name: /Alice Admin/ });
  const bob = page.getByRole("radio", { name: /Bob Reader/ });
  await expect(alice).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  // WebKit injects an inline stylesheet during screenshots that strict CSP rejects.
  if (browserName !== "webkit") {
    const screenshot = testInfo.outputPath("mobile-identity-selection.png");
    await page.screenshot({ path: screenshot, fullPage: true, caret: "initial" });
    await testInfo.attach("mobile identity selection", { path: screenshot, contentType: "image/png" });
  }
  await page.keyboard.press("ArrowDown");
  await expect(bob).toBeChecked();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Continue as selected user" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(`${appOrigin}/`);
  await expect(page.getByLabel("Current session")).toContainText("Bob Reader");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

  const profile = page.locator("article.endpoint").filter({ hasText: "/api/profile" });
  await profile.getByRole("button", { name: "Call endpoint" }).click();
  await expect(profile.locator(".response > strong")).toHaveText("200");
  await expect(profile.locator("pre")).toContainText('"reader"');
  browserMonitor.expectHttpError(403, `${apiOrigin}/api/admin`);
  const admin = page.locator("article.endpoint").filter({ hasText: "/api/admin" });
  await admin.getByRole("button", { name: "Call endpoint" }).click();
  await expect(admin.locator(".response > strong")).toHaveText("403");
});

test("an identity is required before the selection form can submit", async ({
  page,
  browserMonitor: _browserMonitor,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with Hoocloak" }).click();
  await expect(page.getByRole("heading", { name: "Choose an identity" })).toBeVisible();
  const loginUrl = page.url();
  let posts = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/login")) posts += 1;
  });
  await page.getByRole("button", { name: "Continue as selected user" }).click();
  await expect(page).toHaveURL(loginUrl);
  await expect(page.getByRole("radio", { name: /Alice Admin/ })).not.toBeChecked();
  await expect(page.getByRole("radio", { name: /Bob Reader/ })).not.toBeChecked();
  expect(await page.locator("form").evaluate((form) => (form as HTMLFormElement).checkValidity())).toBe(false);
  expect(posts).toBe(0);
});
