import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const repositoryRoot = new URL("../", import.meta.url);
const workflow = readFileSync(new URL(".github/workflows/release.yml", repositoryRoot), "utf8");
const ci = readFileSync(new URL(".github/workflows/ci.yml", repositoryRoot), "utf8");
const readme = readFileSync(new URL("README.md", repositoryRoot), "utf8");
const imageJob = workflow.slice(workflow.indexOf("  publish-image:"), workflow.indexOf("  publish-release:"));

assert.notEqual(imageJob.indexOf("  publish-image:"), -1, "publish-image job must exist");
assert.notEqual(workflow.indexOf("  publish-release:"), -1, "publish-release job must exist");

test("release image staging is digest-only", () => {
  assert.doesNotMatch(workflow, /IMAGE_CANDIDATE_TAG|cand-\$\{\{/);
  assert.match(
    imageJob,
    /outputs: type=image,"name=\$\{\{ env\.GHCR_IMAGE \}\},\$\{\{ env\.DOCKERHUB_IMAGE \}\}",compression=zstd,compression-level=19,force-compression=true,name-canonical=true,push-by-digest=true,push=true/,
  );
  assert.doesNotMatch(imageJob, /^\s+tags:/m);
  assert.match(imageJob, /docker buildx imagetools create[\s\S]*--tag "\$\{image\}:\$\{tag\}"[\s\S]*"\$\{image\}@\$\{INDEX_DIGEST\}"/);
  assert.doesNotMatch(imageJob, /docker buildx imagetools rm/);
});

test("required CI runs release regression before browser setup", () => {
  const nodeInstall = ci.indexOf("run: npm ci --no-audit --no-fund");
  const releaseTest = ci.indexOf("run: npm run test:release-workflow");
  const browserInstall = ci.indexOf("run: npx playwright install --with-deps chromium firefox webkit");

  assert.notEqual(nodeInstall, -1, "CI must install Node dependencies");
  assert.notEqual(releaseTest, -1, "CI must run release workflow regression");
  assert.notEqual(browserInstall, -1, "CI must install Playwright browsers");
  assert.ok(nodeInstall < releaseTest, "release regression must run after npm ci");
  assert.ok(releaseTest < browserInstall, "release regression must run before browser setup");
});

test("protected release instructions preserve the generated message body", () => {
  assert.match(readme, /complete message: subject plus\s+body\/release notes/);
  assert.match(readme, /git fetch origin release\/v<version> && git show -s --format=%B origin\/release\/v<version>/);
  assert.match(readme, /title-only squash is not\s+resumable and prevents publication after CI/);
});
