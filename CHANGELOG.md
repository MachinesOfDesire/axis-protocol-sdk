# Changelog

All notable changes to `axis-protocol-sdk`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`SDK_VERSION` constant is derived from `package.json` so the two cannot drift.

## [Unreleased — 0.2.3]

A side branch [`fix/security-review-unshipped`](https://github.com/MachinesOfDesire/axis-protocol-sdk/tree/fix/security-review-unshipped) carries the **v0.2.3** hardening release, addressing the six remaining unshipped findings from the 2026-05-08/09 security review.

All changes are backward-compatible. Two findings change client-side defaults (HTTPS requirement, fetch timeout) but both ship with explicit escape hatches (`allowInsecure: true`, `timeout: 0`). No wire-protocol changes.

### Added (S-L2, S-M2)

- `AxisClient` constructor option `allowInsecure: boolean` (default `false`). Setting `false` rejects `http://` registry URLs at construction time. Pass `true` for local-dev against a plaintext registry. Closes finding **S-L2**.
- `AxisClient` constructor option `timeout: number` (default `30000`, milliseconds). Per-request timeout backed by `AbortController`. Pass `0` to disable. Slow registries that previously caused indefinite hangs now produce a clean `REGISTRY_UNREACHABLE` after the timeout. Closes finding **S-M2**.

### Fixed

- **S-L1** — `_request` no longer attaches `Authorization` to requests where the endpoint doesn't require auth. Previously, having `apiKey` set caused the Bearer header to be sent on every call, including public endpoints, which leaked the key to the registry's public read paths and to intermediaries that log headers. Public-endpoint methods like `resolveAgent`, `verifyAIT`, `getAccessPolicy` now never send the header even when the client was constructed with an `apiKey`.
- **S-L3** — `AxisClient._slugFromAgentId` uses an explicit grammar (`/^axis:[^:]+:([^:]+)$/`, `/^did:axis:[^:]+:([^:]+)$/`, `/^did:axis:[^:]+:[^:]+:([^:]+)$/`) instead of `.split(":").pop()`. The new implementation handles the v0.2 operator-namespaced DID form `did:axis:{registry}:{operator}:{slug}` (AXIS Protocol v0.2 §4.1) and returns malformed input unchanged rather than silently truncating to the last colon-segment.
- **S-M1** — `signAIT` and `signCanonical` now coerce private-key inputs through a single helper that explicitly checks for `CryptoKey` (via `instanceof` plus duck-typed fallback) or for a JWK (via the RFC-7517-required `kty` field). The old detection `!("type" in privateKey)` was both a false-positive risk (Object.prototype mutations) and a footgun (CryptoKey has a `type` getter, so the negation was wrong on CryptoKey inputs in some hosts).
- **S-M3** — `verifyAIT` routes through `_request()` instead of a parallel fetch path. It now picks up the User-Agent header, AbortController timeout, and consistent error mapping that the rest of the client already had. The `{valid: false, error}` semantic on 4xx token responses is preserved; transport / timeout errors still throw `AxisError(REGISTRY_UNREACHABLE)`.

### Tests

- 24 new tests across `test/client.test.js` (constructor TLS + timeout + auth-scope + slug parsing + verifyAIT routing) and `test/crypto.test.js` (private-key coercion paths)
- Total: 58 tests, 0 failures (was 34)

### Deferred — not in this release

- **S-H2** (canonicalize nested-keys footgun) — locked 2026-05-11 to ship in SDK 0.3.0 alongside the spec v0.2 RFC 8785 JCS migration. Wire-protocol-touching change requiring coordinated registry + SDK + spec landing.

## [Unreleased — 0.2.2]

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
