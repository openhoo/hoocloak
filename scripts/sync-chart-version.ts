import { readFileSync, writeFileSync } from "node:fs";

const version = readFileSync("internal/version/version", "utf8").trim();
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`invalid Hoocloak version: ${JSON.stringify(version)}`);
}

const path = "charts/hoocloak/Chart.yaml";
const chart = readFileSync(path, "utf8")
  .replace(/^version: .*$/m, `version: ${version}`)
  .replace(/^appVersion: .*$/m, `appVersion: "${version}"`);
writeFileSync(path, chart);
