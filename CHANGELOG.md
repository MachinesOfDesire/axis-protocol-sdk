# Changelog

All notable changes to `axis-protocol-sdk`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`SDK_VERSION` constant is derived from `package.json` so the two cannot drift.

## [0.2.2] — 2026-05-08

Security hardening pass against `verifyAITLocally`. All changes are backward
compatible with 0.2.1 callers (existing `verifyAITLocally(token, key)` signatures
keep working) but tokens that pass against 0.2.1 may fail against 0.2.2 if they
lack an `exp` claim. See "Migration notes" below.

### Added

- `verifyAITLocally(token, key, opts)` accepts a third options argument:
  - `audience: string` — when supplied, requires `payload.aud` to match. Closes
    the cross-platform AIT replay class. AXIS v0.2 will likely require this
    server-side; pass it whenever your platform has a stable identifier so a
    token minted for platform A can't be replayed against platform B.
  - `expectedKid: string` — when supplied, requires `header.kid` to match.
    Defends against the footgun where the caller passes a public key that
    doesn't correspond to the kid in the token header.
  - `requireExp: boolean` (default `true`) — reject tokens without an `exp`
    claim. Pass `false` only if you have a deliberate reason (e.g. legacy
    tokens predating exp enforcement).
  - `clockSkew: number` (default `30`, in seconds) — tolerance for `exp`,
    `iat`, and `nbf` checks.
- `nbf` ("not before") claim support: tokens whose `nbf` is in the future
  beyond `clockSkew` are rejected.
- 6 new tests covering audience enforcement, kid mismatch, missing exp,
  future iat, and clock-skew tolerance. SDK now has 40 tests, all passing.

### Changed

- `verifyAITLocally` now rejects tokens whose `iat` is in the future beyond
  `clockSkew` seconds. Previously, future `iat` was silently accepted.
- Default clock-skew tolerance for `exp` is now 30 seconds. Previously, any
  token past `exp` was rejected immediately.
- JSDoc on `canonicalize()` now documents the nested-key footgun (the
  `JSON.stringify(obj, Object.keys(obj).sort())` pattern only filters keys at
  every nesting level, not recursively sorts them, and strips nested keys
  whose names don't appear at the top level). Wire-format compat with the
  registry is preserved (both sides use the same broken algorithm); v0.2
  spec work should standardize on RFC 8785 JCS.

### Migration notes (0.2.1 → 0.2.2)

- If you produce AITs via `signAIT()` from this SDK or via the registry, you
  are unaffected — both always set `exp`.
- If you consume hand-crafted AITs without `exp`, pass `{ requireExp: false }`
  to keep current behavior. Recommended: add `exp` instead.
- If your platform has a stable identifier, pass `{ audience: "your-id" }`
  and ensure issuers set `aud` accordingly.
- If you know which agent's key you're verifying against (you almost always
  do), pass `{ expectedKid: agent_id }` to defend against accidental
  key-mismatch.

## [0.2.1] — 2026-05-04

### Added

- `SDK_VERSION` constant now derived from `package.json` so the two cannot
  drift.

### Fixed

- `createDelegation`: dropped the legacy `expires_at` parameter alias.
  Canonical field name is `expires` per AXIS Protocol Spec v0.1 §4.4.
- `createAgent`: `operator_id` fallback reconstructs the canonical
  `axis:{slug}:operator` form when older registry shapes return only the
  bare slug nested under `document.axisMetadata.operator.id`.
- CI: shell-quote escaping in the no-deps check; explicit test file
  enumeration for Node 20 compatibility.

## [0.2.0] — 2026-04-29

### Changed

- Aligned `createDelegation` body with AXIS Protocol Spec v0.1: required
  fields are `issued_by`, `issued_to`, `root_operator`, `scope`, `expires`.

## [0.1.0] — 2026-04-23

Initial public release. Universal client: Node 20+, Cloudflare Workers,
Deno, Bun, modern browsers. Zero runtime dependencies. ESM-only.

Surface:
- `AxisClient` covering public, registrar, and admin/super_admin endpoints
- Crypto helpers: `generateKeypair`, `signAIT`, `verifyAITLocally`,
  `decodeAIT`, `importPrivateKey`, `importPublicKey`, `canonicalize`,
  `signCanonical`
- `AxisError` with stable error codes
