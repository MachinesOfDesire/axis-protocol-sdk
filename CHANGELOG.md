# Changelog

All notable changes to `axis-protocol-sdk`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`SDK_VERSION` constant is derived from `package.json` so the two cannot drift.

## [Unreleased]

A side branch [`security-hardening-2026-05-08`](https://github.com/MachinesOfDesire/axis-protocol-sdk/tree/security-hardening-2026-05-08) carries a substantial **v0.2.2** release awaiting review:

- Adds optional `audience` and `expectedKid` opts to `verifyAITLocally`
- Requires `exp` claim by default (opt-out via `requireExp: false`)
- Rejects tokens with `iat` in the future beyond the configured clock skew (default 30s)
- Adds `nbf` support
- Documents a `canonicalize()` nested-key footgun in JSDoc — interop with the registry preserved (both sides use the same shallow algorithm), flagged for AXIS spec v0.2 to switch to RFC 8785 JCS
- Backward compatible: existing `verifyAITLocally(token, key)` callers unchanged
- 6 new tests (40/40 passing)

The branch carries its own draft CHANGELOG entry with full migration notes. When the branch merges to `main`, this `[Unreleased]` block is replaced by the full `[0.2.2]` entry.

The single commit on `main` since `v0.2.1` (`ba34b86`, examples/delegation.js field-name fix) is also folded into the upcoming v0.2.2 — the `[0.2.2]` entry on the side branch describes it under "Fixed".

## [0.2.1] — 2026-05-04

### Refactored

- `SDK_VERSION` is now derived from `package.json` via JSON import attribute, eliminating the drift class that produced the `v0.2.0` constant alongside a `v0.2.1` `package.json` earlier the same day. Supported on Node 20+, Cloudflare Workers (esbuild inlines), Deno, Bun, and modern browsers.

### Fixed

- `createDelegation` aligned with AXIS Protocol Spec v0.1 §4.4: canonical timestamp field is `expires` (legacy `expires_at` alias dropped). Required `root_operator` parameter added. Optional `constraints`, `parent_credential_id`, and `signature` parameters surfaced.
- `register.js` response now includes `operator_id` at the top level of the AIR (additive, backwards-compatible).
- `/verify` endpoint returns the canonical `operator_id` from the agent row (was reading `payload.operator_id` which the SDK never writes; comment rows were stored with `axis_operator_id: null` until this fix). Deployed to production registry as version `17142d7e` on 2026-05-02.

### CI

- Test workflow enumerates test files explicitly so Node 20 and Node 22 both run the suite (Node 20 does not expand globs in `--test` arguments).
- Verifies zero runtime dependencies on every push.
- Matrix: Node 20 + 22 on Ubuntu, Node 22 on Windows + macOS.

## [0.2.0] — 2026-04-29

Initial public-ready cut of the JS SDK. Zero runtime dependencies, ESM-only, runs in Node 20+, Cloudflare Workers, Deno, Bun, and modern browsers.

- `AxisClient` covering public, registrar, and admin/super_admin roles with stable error codes
- Crypto helpers: `generateKeypair`, `signAIT`, `verifyAITLocally`, `decodeAIT`, `canonicalize`, `signCanonical`, `importPrivateKey`, `importPublicKey`
- Base64url helpers (`b64urlEncode`, `b64urlDecode`, `b64urlDecodeString`)
- Full `AxisError` class with stable `ERR.*` code constants
