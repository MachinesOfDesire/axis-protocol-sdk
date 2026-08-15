// GENERATED — do not edit by hand. scripts/sync-version.mjs rewrites this from
// package.json's "version" via the `npm version` lifecycle, and
// test/version.test.js fails if the two drift.
//
// This file exists so no runtime module imports package.json. That import
// needed an import attribute (`with { type: "json" }`), and while every
// runtime the SDK targets supports attributes, a CONSUMER'S BUNDLER must also
// parse them — and older bundlers still in wide use hard-fail (wrangler 3's
// bundled esbuild: `Expected ";" but found "with"`), breaking the consumer's
// build. A plain constant is parseable by everything.
export const SDK_VERSION = "0.3.1";
