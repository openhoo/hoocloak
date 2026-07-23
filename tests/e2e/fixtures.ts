import { expect, test as base } from "@playwright/test";

function origin(originName: string, portName: string, hostname: string, fallbackPort: number): string {
  const configuredOrigin = process.env[originName];
  if (configuredOrigin !== undefined) {
    return configuredOrigin;
  }
  return `http://${hostname}:${process.env[portName] ?? fallbackPort}`;
}

export const appOrigin = origin("E2E_SPA_ORIGIN", "E2E_SPA_PORT", "localhost", 13_000);
export const providerOrigin = origin(
  "E2E_PROVIDER_ORIGIN",
  "E2E_PROVIDER_PORT",
  "hoocloak.localhost",
  18_080,
);
export const apiOrigin = origin(
  "E2E_API_ORIGIN",
  "E2E_API_PORT",
  "api.localhost",
  15_099,
);

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
