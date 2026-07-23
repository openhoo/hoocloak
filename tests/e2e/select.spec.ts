import { expect, test } from "./fixtures";

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

  await expect(page).toHaveURL("http://localhost:13000/");
  await expect(page.getByLabel("Current session")).toContainText("Alice Admin");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL("http://localhost:13000/");
  await expect(
    page.getByRole("heading", { name: "No development identity is active" }),
  ).toBeVisible();
});
