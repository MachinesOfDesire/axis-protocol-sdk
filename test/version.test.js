// SDK_VERSION integrity + the import-attribute regression gate.
//
// v0.2.3 shipped `import pkg from "../package.json" with { type: "json" }` in
// src/index.js. Import attributes run fine on every runtime the SDK targets,
// but a CONSUMER'S BUNDLER must also parse them, and older bundlers still in
// wide use hard-fail — wrangler 3's bundled esbuild rejects the file with
// `Expected ";" but found "with"`, which broke `wrangler dev` for Workers
// projects depending on the SDK. These tests keep published src/ free of
// import attributes and keep the replacement constant from drifting.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { SDK_VERSION } from "../src/version.js";

test("SDK_VERSION matches package.json version", () => {
  const pkg = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.equal(
    SDK_VERSION,
    pkg.version,
    "src/version.js drifted from package.json — run: node scripts/sync-version.mjs",
  );
});

test("no file in src/ uses an import attribute", () => {
  const dir = new URL("../src/", import.meta.url);
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".js")) continue;
    const text = readFileSync(new URL(file, dir), "utf8");
    // Matches `import ... with {` and dynamic `import(..., { with: ...`.
    const attributeShapes = [
      /^\s*import\b[^;]*?\bwith\s*\{/ms,
      /\bimport\s*\([^)]*\bwith\s*:/s,
    ];
    for (const shape of attributeShapes) {
      assert.ok(
        !shape.test(text),
        `src/${file} appears to use an import attribute (${shape}) — ` +
          "older consumer bundlers (e.g. wrangler 3's esbuild) cannot parse these",
      );
    }
  }
});
