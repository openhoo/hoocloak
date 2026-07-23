import { randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createServer } from "node:net";
import { defineConfig, devices } from "@playwright/test";

function configuredPort(name: string): number | undefined {
  const configured = process.env[name];
  if (configured === undefined) {
    return undefined;
  }
  const port = Number(configured);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${name} must be an integer between 1 and 65535`);
  }
  return port;
}

const allocationLockPath = join(dirname(fileURLToPath(import.meta.url)), ".playwright-e2e.lock");
const handledSignals = [
  ["SIGHUP", 129],
  ["SIGINT", 130],
  ["SIGQUIT", 131],
  ["SIGTERM", 143],
] as const;

function lockOwnerIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function recoverStaleAllocationLock(): boolean {
  try {
    const owner = JSON.parse(readFileSync(allocationLockPath, "utf8")) as { pid?: unknown };
    if (typeof owner.pid === "number" && Number.isInteger(owner.pid) && lockOwnerIsAlive(owner.pid)) {
      return false;
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return true;
    }

    // A newly-created lock can briefly be empty while its owner writes metadata.
    try {
      if (Date.now() - statSync(allocationLockPath).mtimeMs < 30_000) {
        return false;
      }
    } catch (statError) {
      if ((statError as NodeJS.ErrnoException).code === "ENOENT") {
        return true;
      }
      throw statError;
    }
  }

  try {
    rmSync(allocationLockPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
  return true;
}

async function acquireAllocationLock(): Promise<() => void> {
  let announcedWait = false;
  while (true) {
    try {
      const descriptor = openSync(allocationLockPath, "wx", 0o600);
      try {
        writeFileSync(descriptor, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }));
      } finally {
        closeSync(descriptor);
      }

      let released = false;
      const release = () => {
        if (released) {
          return;
        }
        released = true;
        try {
          rmSync(allocationLockPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
          }
        }
      };

      process.once("exit", release);
      for (const [signal, exitCode] of handledSignals) {
        process.once(signal, () => {
          // Playwright owns graceful webServer shutdown. This is only a bounded fallback
          // that releases the lock if its signal handling cannot complete.
          const forcedExit = setTimeout(() => {
            release();
            process.exit(exitCode);
          }, 30_000);
          forcedExit.unref();
        });
      }
      return release;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }

    if (recoverStaleAllocationLock()) {
      continue;
    }
    if (!announcedWait) {
      console.error(`Waiting for E2E allocation lock at ${allocationLockPath}`);
      announcedWait = true;
    }
    await delay(100);
  }
}

async function availablePort(excluded: ReadonlySet<number>): Promise<number> {
  while (true) {
    const { promise, resolve, reject } = Promise.withResolvers<number>();
    const server = createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("Unable to allocate an E2E port"));
        return;
      }
      server.close((error) => (error ? reject(error) : resolve(address.port)));
    });
    const port = await promise;
    if (!excluded.has(port)) {
      return port;
    }
  }
}

const configuredPorts = {
  provider: configuredPort("E2E_PROVIDER_PORT"),
  api: configuredPort("E2E_API_PORT"),
  spa: configuredPort("E2E_SPA_PORT"),
};
const explicitPorts = Object.values(configuredPorts).filter(
  (port): port is number => port !== undefined,
);
if (new Set(explicitPorts).size !== explicitPorts.length) {
  throw new Error("E2E_PROVIDER_PORT, E2E_API_PORT, and E2E_SPA_PORT must be distinct");
}

const usesDynamicPorts = Object.values(configuredPorts).some((port) => port === undefined);
if (usesDynamicPorts) {
  await acquireAllocationLock();
}

const allocatedPorts = new Set(explicitPorts);
const providerPort = configuredPorts.provider ?? (await availablePort(allocatedPorts));
allocatedPorts.add(providerPort);
const apiPort = configuredPorts.api ?? (await availablePort(allocatedPorts));
allocatedPorts.add(apiPort);
const spaPort = configuredPorts.spa ?? (await availablePort(allocatedPorts));

const e2eEnv = {
  E2E_PROVIDER_PORT: String(providerPort),
  E2E_API_PORT: String(apiPort),
  E2E_SPA_PORT: String(spaPort),
  E2E_PROVIDER_ORIGIN: `http://hoocloak.localhost:${providerPort}`,
  E2E_API_ORIGIN: `http://api.localhost:${apiPort}`,
  E2E_SPA_ORIGIN: `http://localhost:${spaPort}`,
  COMPOSE_PROJECT_NAME:
    process.env.COMPOSE_PROJECT_NAME ??
    `hoocloak-e2e-${process.pid}-${randomBytes(4).toString("hex")}`,
};

Object.assign(process.env, e2eEnv);

export default defineConfig({
  testDir: "./tests/e2e",
  outputDir: "test-results",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  // Every browser exercises the same stateful provider stack. One worker retains
  // cross-browser coverage without allowing one project to revoke another's state.
  workers: 1,
  reporter: process.env.CI
    ? [["line"], ["html", { open: "never" }]]
    : [["list"], ["html", { open: "never" }]],
  timeout: 30_000,
  expect: {
    timeout: 7_500,
  },
  use: {
    baseURL: e2eEnv.E2E_SPA_ORIGIN,
    screenshot: "only-on-failure",
    trace: "on-first-retry",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
  webServer: {
    command: "npm run e2e:server",
    url: e2eEnv.E2E_SPA_ORIGIN,
    env: {
      ...process.env,
      ...e2eEnv,
    },
    reuseExistingServer: process.env.PW_REUSE_SERVER === "1",
    gracefulShutdown: {
      signal: "SIGTERM",
      timeout: 30_000,
    },
    timeout: 5 * 60_000,
  },
});
