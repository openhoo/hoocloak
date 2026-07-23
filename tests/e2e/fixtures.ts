import { expect, test as base } from "@playwright/test";

type BrowserMonitor = {
  expectHttpError(status: number, url: string): void;
};

type CleanBrowserFixtures = {
  browserMonitor: BrowserMonitor;
};

export const test = base.extend<CleanBrowserFixtures>({
  browserMonitor: async ({ page }, use) => {
    const errors: string[] = [];
    const expectedHttpErrors: string[] = [];
    const observedHttpErrors: string[] = [];

    page.on("console", (message) => {
      if (message.type() === "error") {
        if (message.text().startsWith("Failed to load resource: the server responded with a status of")) {
          return;
        }
        const location = message.location();
        const source = location.url
          ? ` (${location.url}:${location.lineNumber}:${location.columnNumber})`
          : "";
        errors.push(`console: ${message.text()}${source}`);
      }
    });
    page.on("pageerror", (error) => {
      errors.push(`page: ${error.message}`);
    });
    page.on("response", (response) => {
      if (response.status() >= 400) {
        observedHttpErrors.push(`${response.status()} ${response.url()}`);
      }
    });

    await use({
      expectHttpError(status, url) {
        expectedHttpErrors.push(`${status} ${url}`);
      },
    });
    expect
      .soft(observedHttpErrors.sort(), "browser received only expected HTTP errors")
      .toEqual(expectedHttpErrors.sort());
    expect.soft(errors, "browser emitted no console or page errors").toEqual([]);
  },
});

export { expect } from "@playwright/test";
