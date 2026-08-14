// Rewrite src/version.js's SDK_VERSION from package.json.
//
// Wired into the `npm version` lifecycle (package.json "scripts.version"), so
// `npm version patch|minor|major` regenerates and stages the constant in the
// same commit as the package.json bump. Can also be run by hand:
//
//   node scripts/sync-version.mjs
//
// test/version.test.js is the backstop for edits that bypass `npm version`.

import { readFileSync, writeFileSync } from "node:fs";

const pkgUrl = new URL("../package.json", import.meta.url);
const versionUrl = new URL("../src/version.js", import.meta.url);

const { version } = JSON.parse(readFileSync(pkgUrl, "utf8"));
const source = readFileSync(versionUrl, "utf8");
const updated = source.replace(
  /export const SDK_VERSION = "[^"]*";/,
  `export const SDK_VERSION = "${version}";`,
);
if (updated === source && !updated.includes(`"${version}"`)) {
  console.error("sync-version: could not find the SDK_VERSION line in src/version.js");
  process.exit(1);
}
writeFileSync(versionUrl, updated);
console.log(`sync-version: src/version.js -> ${version}`);
