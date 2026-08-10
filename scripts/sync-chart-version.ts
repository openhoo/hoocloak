import { readFileSync, writeFileSync } from "node:fs";

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const version = readFileSync("internal/version/version", "utf8").trim();
if (!semverPattern.test(version)) {
  throw new Error(`invalid Hoocloak version: ${JSON.stringify(version)}`);
}

const path = "charts/hoocloak/Chart.yaml";
const chart = readFileSync(path, "utf8");
const versionFields = [...chart.matchAll(/^version:.*$/gm)];
const appVersionFields = [...chart.matchAll(/^appVersion:.*$/gm)];
const canonicalVersionFields = [...chart.matchAll(/^version: ([^\s"'\r\n]+)$/gm)];
const canonicalAppVersionFields = [...chart.matchAll(/^appVersion: "([^"\r\n]*)"$/gm)];

if (versionFields.length !== 1 || canonicalVersionFields.length !== 1) {
  throw new Error("Chart.yaml must contain exactly one canonical unquoted version field");
}
if (appVersionFields.length !== 1 || canonicalAppVersionFields.length !== 1) {
  throw new Error('Chart.yaml must contain exactly one canonical double-quoted appVersion field');
}
if (!semverPattern.test(canonicalVersionFields[0][1]) ||
    !semverPattern.test(canonicalAppVersionFields[0][1])) {
  throw new Error("Chart.yaml version fields must contain valid semantic versions");
}

const updated = chart
  .replace(/^version: ([^\s"'\r\n]+)$/m, `version: ${version}`)
  .replace(/^appVersion: "([^"\r\n]*)"$/m, `appVersion: "${version}"`);
const updatedVersionFields = [...updated.matchAll(/^version: ([^\s"'\r\n]+)$/gm)];
const updatedAppVersionFields = [...updated.matchAll(/^appVersion: "([^"\r\n]*)"$/gm)];
if (updatedVersionFields.length !== 1 || updatedVersionFields[0][1] !== version ||
    updatedAppVersionFields.length !== 1 || updatedAppVersionFields[0][1] !== version) {
  throw new Error("Chart.yaml version synchronization verification failed");
}

writeFileSync(path, updated);
