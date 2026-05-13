# Changelog

All notable changes to `axis-protocol-sdk`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`SDK_VERSION` constant is derived from `package.json` so the two cannot drift.

## [0.2.3] — 2026-05-12

Two coordinated fixes that close axis-comments WC-M2 and WC-L4 on the SDK side. Both purely additive; existing 0.2.2 callers unchanged.

### Added — `presentingAIT` option on public-endpoint methods (WC-M2)

`resolveAgent`, `resolveDid`, and `getOperator` accept a `{ presentingAIT: string }` option. When supplied, the SDK sends `Authorization: Bearer <ait>` on the request, which causes the registry to return the presentation layer (display_name, verification_tier, etc.) per AXIS Protocol v0.1.1 §5.2.

```js
// Verify an AIT, then fetch presentation-layer fields for that agent.
const verify = await client.verifyAIT(token);
if (verify.valid) {
  const agent = await client.resolveAgent(verify.agent_id, { presentingAIT: token });
  console.log(agent.display_name, agent.operator_verification_tier);
}
```

This replaces the v0.2.1 workaround where callers (e.g. axis-comments-ghost) constructed a per-call `AxisClient` with the AIT in the `apiKey` slot to flip the Bearer header. The workaround broke silently in v0.2.2's S-L1 hardening (S-L1 stopped sending Authorization on public endpoints unconditionally). `presentingAIT` is the correct API.

Negative-test coverage: `presentingAIT` does NOT leak the constructor-time `apiKey` even when both are set on the same client; the AIT takes precedence for that call.

### Added — `code` field surfaced on `verifyAIT` valid:false responses (WC-L4)

`verifyAIT(token)` now returns a structured `code` alongside the existing `error` string:

```js
const result = await client.verifyAIT(token);
// {
//   valid: false,
//   code: "token_expired",  // or "invalid_signature", "agent_revoked", "agent_suspended", etc.
//   error: "Token expired",
//   agent_id: "axis:op:agent",
// }
```

Codes mirror what the registry emits (axis-registry v0.1.3+). For older registries that don't yet emit `code`, the field is `null` and callers fall back to error-string classification. The no-token case (`verifyAIT("")`) returns `code: "missing_token"` immediately without a registry call.

This closes WC-L4 on the SDK side. The registry-side change (axis-registry PR #18) and the axis-comments-ghost-side change (consume `code` instead of regex-matching the reason string) ship in coordination.

### Tests

- 7 new tests in `test/client.test.js` covering both additions
- Total: 71 tests, 0 failures (was 64 at 0.2.2)

### Migration notes (0.2.2 → 0.2.3)

Both changes are additive. Existing callers don't need to change anything.

- Code that needs presentation-layer data after AIT verification: use `presentingAIT` on the resolve call. The v0.2.1 apiKey-slot workaround is broken under 0.2.2+ and should be replaced.
- Code that classifies `verifyAIT` failures: prefer `result.code` (machine-readable) over `result.error` (free text). Keep a regex fallback for the case where `code` is null (older registries).

## [0.2.2] — 2026-05-12

Security hardening pass landing **all eight** findings from the 2026-05-08/09 security review that are not deferred. Mostly backward-compatible with 0.2.1 callers; two consumer-visible behavioral changes are documented under "Migration notes" with explicit escape hatches.

No wire-protocol changes. One finding (S-H2, canonicalize nested-keys footgun) is deferred to SDK 0.3.0 alongside the spec v0.2 RFC 8785 JCS migration.

### Added — `verifyAITLocally` hardening (S-H1)

- `verifyAITLocally(token, key, opts)` accepts a third options argument:
  - `audience: string` — when supplied, requires `payload.aud` to match. Closes the cross-platform AIT replay class. AXIS v0.2 will likely require this server-side; pass it whenever your platform has a stable identifier so a token minted for platform A can't be replayed against platform B.
  - `expectedKid: string` — when supplied, requires `header.kid` to match. Defends against the footgun where the caller passes a public key that doesn't correspond to the kid in the token header.
  - `requireExp: boolean` (default `true`) — reject tokens without an `exp` claim. Pass `false` only if you have a deliberate reason (e.g. legacy tokens predating exp enforcement).
  - `clockSkew: number` (default `30`, in seconds) — tolerance for `exp`, `iat`, and `nbf` checks.
- `nbf` ("not before") claim support: tokens whose `nbf` is in the future beyond `clockSkew` are rejected.

### Added — `AxisClient` constructor options (S-L2, S-M2)

- `allowInsecure: boolean` (default `false`). Rejects `http://` registry URLs at construction time. Pass `true` for local-dev against a plaintext registry. Closes finding **S-L2**.
- `timeout: number` (default `30000`, milliseconds). Per-request timeout backed by `AbortController`. Pass `0` to disable. Slow registries that previously caused indefinite hangs now produce a clean `REGISTRY_UNREACHABLE` after the timeout. Closes finding **S-M2**.

### Changed

- `verifyAITLocally` now rejects tokens whose `iat` is in the future beyond `clockSkew` seconds. Previously, future `iat` was silently accepted.
- Default clock-skew tolerance for `exp` is now 30 seconds. Previously, any token past `exp` was rejected immediately.
- JSDoc on `canonicalize()` now documents the nested-key footgun (the `JSON.stringify(obj, Object.keys(obj).sort())` pattern only filters keys at every nesting level, not recursively sorts them, and strips nested keys whose names don't appear at the top level). Wire-format compat with the registry is preserved (both sides use the same broken algorithm); v0.2 spec work standardizes on RFC 8785 JCS.

### Fixed

- **S-L1** — `_request` no longer attaches `Authorization` to requests where the endpoint doesn't require auth. Previously, having `apiKey` set caused the Bearer header to be sent on every call, including public endpoints, which leaked the key to the registry's public read paths and to intermediaries that log headers. Public-endpoint methods like `resolveAgent`, `verifyAIT`, `getAccessPolicy` now never send the header even when the client was constructed with an `apiKey`.
- **S-L3** — `AxisClient._slugFromAgentId` uses an explicit grammar (`/^axis:[^:]+:([^:]+)$/`, `/^did:axis:[^:]+:([^:]+)$/`, `/^did:axis:[^:]+:[^:]+:([^:]+)$/`) instead of `.split(":").pop()`. The new implementation handles the v0.2 operator-namespaced DID form `did:axis:{registry}:{operator}:{slug}` (AXIS Protocol v0.2 §4.1) and returns malformed input unchanged rather than silently truncating to the last colon-segment.
- **S-L4** — `verifyAITLocally` now consistently returns `{ valid: false, error }` for every invalid-token shape (bad signature, expired, missing claims, etc.). Previously it returned `{valid:false}` for bad signatures but threw for expired tokens.
- **S-M1** — `signAIT` and `signCanonical` now coerce private-key inputs through a single helper that explicitly checks for `CryptoKey` (via `instanceof` plus duck-typed fallback) or for a JWK (via the RFC-7517-required `kty` field). The old detection `!("type" in privateKey)` was both a false-positive risk (Object.prototype mutations) and a footgun (CryptoKey has a `type` getter, so the negation was wrong on CryptoKey inputs in some hosts).
- **S-M3** — `verifyAIT` routes through `_request()` instead of a parallel fetch path. It now picks up the User-Agent header, AbortController timeout, and consistent error mapping that the rest of the client already had. The `{valid: false, error}` semantic on 4xx token responses is preserved; transport / timeout errors still throw `AxisError(REGISTRY_UNREACHABLE)`.

### Tests

- 30 new tests across `test/client.test.js` and `test/crypto.test.js`
- Total: 64 tests, 0 failures (was 34 at 0.2.1)

### Migration notes (0.2.1 → 0.2.2)

| Concern | Action |
|---|---|
| You produce AITs via `signAIT()` (this SDK) or via the registry | No action — both always set `exp`. |
| You consume hand-crafted AITs without `exp` | Pass `{ requireExp: false }` to `verifyAITLocally` to keep current behavior. Recommended: add `exp` to your issuer instead. |
| Your platform has a stable identifier | Pass `{ audience: "your-id" }` to `verifyAITLocally` and ensure issuers set `aud` accordingly. |
| You know which agent's key you're verifying against | Pass `{ expectedKid: agent_id }` to defend against accidental key-mismatch. |
| You use `http://` registry URLs (local dev) | Pass `{ allowInsecure: true }` to `AxisClient`. |
| Your registry takes longer than 30s to respond | Pass `{ timeout: 0 }` or a custom millisecond value to `AxisClient`. |
| You construct `AxisClient` with `apiKey` | No action — public-endpoint calls correctly stop attaching Authorization. If anything relied on the header being sent, that reliance was a bug. |

### Deferred — not in this release

- **S-H2** (canonicalize nested-keys footgun) — locked 2026-05-11 to ship in SDK 0.3.0 alongside the spec v0.2 RFC 8785 JCS migration. Wire-protocol-touching change requiring coordinated registry + SDK + spec landing.

## [0.2.1] — 2026-05-04

### Refactored

- `SDK_VERSION` is now derived from `package.json` via JSON import attribute, eliminating the drift class that produced the `v0.2.0` constant alongside a `v0.2.1` `package.json` earlier the same day. Supported on Node 20+, Cloudflare Workers (esbuild inlines), Deno, Bun, and modern browsers.

### Fixed

- `createDelegation` aligned with AXIS Protocol Spec v0.1 §4.4: canonical timestamp field is `expires` (legacy `expires_at` alias dropped). Required `root_operator` parameter added. Optional `constraints`, `parent_credential_id`, and `signature` parameters surfaced.
- `register.js` response now includes `operator_id` at the top level of the AIR (additive, backwards-compatible).
- `/verify` endpoint returns the canonical `operator_id` from the agent row (was reading `payload.operator_id` which the SDK never writes). Deployed to production registry on 2026-05-02.

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
