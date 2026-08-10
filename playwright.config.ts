import { randomBytes } from "node:crypto";
import {
  closeSync,
  futimesSync,
  renameSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
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
const allocationLockMetadataPath = `${allocationLockPath}.metadata`;
const allocationLockWaitTimeoutMs = 30 * 60_000;
const allocationLockHeartbeatIntervalMs = 30_000;
const allocationLockLeaseMs = 10 * 60_000;

function lockOwnerIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

type AllocationLockOwner = {
  pid: number;
  createdAt: string;
  ownerToken: string;
};

function allocationLockCleanupError(reason: string): Error {
  return new Error(
    `${reason}. The allocation lock was not removed because only its owner may unlink it. ` +
      `After verifying that no E2E run owns it, remove it manually: rm -- ${JSON.stringify(allocationLockMetadataPath)} ${JSON.stringify(allocationLockPath)}`,
  );
}

function readAllocationLockOwner(): AllocationLockOwner | undefined {
  let contents: string;
  try {
    contents = readFileSync(allocationLockMetadataPath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }

  try {
    const owner = JSON.parse(contents) as Partial<AllocationLockOwner>;
    if (
      typeof owner.pid !== "number" ||
      !Number.isSafeInteger(owner.pid) ||
      owner.pid <= 0 ||
      typeof owner.createdAt !== "string" ||
      !Number.isFinite(Date.parse(owner.createdAt)) ||
      typeof owner.ownerToken !== "string" ||
      owner.ownerToken.length === 0
    ) {
      throw new Error("invalid allocation lock metadata");
    }
    return owner as AllocationLockOwner;
  } catch {
    throw allocationLockCleanupError(
      `The E2E allocation lock at ${allocationLockPath} contains malformed metadata`,
    );
  }
}

async function acquireAllocationLock(): Promise<() => void> {
  const waitDeadline = Date.now() + allocationLockWaitTimeoutMs;
  let announcedWait = false;
  while (true) {
    const ownerToken = randomBytes(32).toString("hex");
    let descriptor: number;
    try {
      descriptor = openSync(allocationLockPath, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
      const owner = readAllocationLockOwner();
      let heartbeatAgeMs: number;
      try {
        heartbeatAgeMs = Date.now() - statSync(allocationLockPath).mtimeMs;
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") {
          if (Date.now() >= waitDeadline) {
            throw allocationLockCleanupError(
              `Timed out after ${allocationLockWaitTimeoutMs}ms waiting for the E2E allocation lock at ${allocationLockPath}`,
            );
          }
          continue;
        }
        throw statError;
      }
      if (owner === undefined) {
        if (heartbeatAgeMs >= allocationLockLeaseMs) {
          throw allocationLockCleanupError(
            `The E2E allocation lock at ${allocationLockPath} has incomplete metadata and no fresh heartbeat`,
          );
        }
      } else if (!lockOwnerIsAlive(owner.pid) || heartbeatAgeMs >= allocationLockLeaseMs) {
        const confirmedOwner = readAllocationLockOwner();
        if (confirmedOwner?.ownerToken !== owner.ownerToken) {
          if (Date.now() >= waitDeadline) {
            throw allocationLockCleanupError(
              `Timed out after ${allocationLockWaitTimeoutMs}ms waiting for the E2E allocation lock at ${allocationLockPath}`,
            );
          }
          continue;
        }
        const reason = lockOwnerIsAlive(owner.pid)
          ? `has not refreshed its heartbeat for ${Math.floor(heartbeatAgeMs / 1_000)} seconds`
          : `belongs to dead process ${owner.pid}`;
        throw allocationLockCleanupError(
          `The E2E allocation lock at ${allocationLockPath} ${reason}`,
        );
      }
      if (Date.now() >= waitDeadline) {
        throw allocationLockCleanupError(
          `Timed out after ${allocationLockWaitTimeoutMs}ms waiting for the E2E allocation lock at ${allocationLockPath}`,
        );
      }
      if (!announcedWait) {
        console.error(`Waiting for E2E allocation lock at ${allocationLockPath}`);
        announcedWait = true;
      }
      await delay(100);
      continue;
    }

    let temporaryPath: string | undefined;
    try {
      try {
        rmSync(allocationLockMetadataPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
      temporaryPath = `${allocationLockMetadataPath}.${process.pid}.${ownerToken}.tmp`;
      const metadataDescriptor = openSync(temporaryPath, "wx", 0o600);
      try {
        writeFileSync(
          metadataDescriptor,
          JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString(), ownerToken }),
        );
      } finally {
        closeSync(metadataDescriptor);
      }
      renameSync(temporaryPath, allocationLockMetadataPath);
    } catch (error) {
      try {
        rmSync(allocationLockPath);
      } catch (cleanupError) {
        if ((cleanupError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw cleanupError;
        }
      }
      throw error;
    } finally {
      if (temporaryPath !== undefined) {
        try {
          rmSync(temporaryPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
          }
        }
      }
    }

    const heartbeat = setInterval(() => {
      try {
        if (readAllocationLockOwner()?.ownerToken !== ownerToken) {
          clearInterval(heartbeat);
          return;
        }
        const now = new Date();
        futimesSync(descriptor, now, now);
      } catch {
        clearInterval(heartbeat);
      }
    }, allocationLockHeartbeatIntervalMs);
    heartbeat.unref();

    let released = false;
    const release = () => {
      if (released) {
        return;
      }
      released = true;
      clearInterval(heartbeat);
      try {
        const owner = readAllocationLockOwner();
        if (owner?.ownerToken === ownerToken) {
          for (const path of [allocationLockMetadataPath, allocationLockPath]) {
            try {
              rmSync(path);
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
                throw error;
              }
            }
          }
        }
      } finally {
        closeSync(descriptor);
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
