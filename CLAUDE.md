# Claude Code Instructions — axis-protocol-sdk

## First action every session

1. Read this file
2. Open the Kipple Labs Manifest in Notion: https://www.notion.so/35df359483b2817a97c5e9c7a5169e85
3. Read the Corporate Canon in Notion: https://www.notion.so/35df359483b28183a02ac7603504b904
4. Read the AXIS Protocol Canon in Notion (the SDK is a downstream consumer of the spec): https://www.notion.so/35df359483b281848efae1f258ba0458
5. Check the Cross-Project Coordination database, filtered to items where Affects includes "AXIS Protocol" or "AXIS Prime" and Status is Open or In progress: https://www.notion.so/d2f90b6b9d384973abfbb25b17592d20
6. Read the AXIS Command Center hub: https://www.notion.so/347f359483b281ec8848fba6ff6ae38b
7. Check the Version Coordination Log if your work touches the SDK version or the AXIS Protocol version it speaks: https://www.notion.so/35df359483b281c98747fa47df0b1a65

If any of those documents are missing or contradict each other, STOP and surface to Josh.

## Project scope

`axis-protocol-sdk` is the reference JavaScript client library for the AXIS Protocol. One package on npm. Three things it does:

- **Generates keypairs** an agent uses to prove its identity (Ed25519 / EdDSA per RFC 8037)
- **Signs and verifies AXIS Identity Tokens (AITs)** — JWT-shaped tokens an agent presents to a platform
- **Talks to a registry** — registers agents, looks up identities, issues / revokes delegations

The SDK is the canonical client for every AXIS consumer in JavaScript runtimes (Node 20+, Cloudflare Workers, Deno, Bun, modern browsers). A Python sibling (`axis-protocol-sdk-python`) lives in a separate repo.

This Project's scope:

- The SDK codebase under `src/`, `test/`, `examples/`
- npm package publishing readiness
- SDK security hardening (per the 2026-05-08/09 security review)
- Conformance with AXIS Protocol spec (downstream consumer of `axis-protocol` v0.1.1 today)
- Zero-runtime-dependency commitment — the SDK uses only Web Crypto, `fetch`, `TextEncoder`, base64 helpers

This Project does NOT do:

- AXIS Protocol specification changes — raise as cross-project Coordination items; Assigned to (Project) = "AXIS Protocol"
- AXIS Prime registry / `axis-registry` changes — raise as cross-project Coordination items; Assigned to (Project) = "AXIS Prime"
- The Python SDK (`axis-protocol-sdk-python`) — separate Project, separate session
- Application-layer consumers (axis-comments, axis-gateway, N7) — separate Projects
- Legal / IP / canonical content — Corporate, requires Josh + attorney

## Files I cannot modify without explicit instruction

- `LICENSE` (copyright line)
- `NOTICE`
- `README.md` (copyright footer, governance section, license section, author line)
- `CONTRIBUTING.md` (CLA grantee language, maintainer reference)
- `CONTRIBUTORS.md`
- `package.json` `author`, `license` fields (canonical)
- Copyright headers in any source files
- Any ratified ADR (if added under `docs/adr/` in the future)
- This file (`CLAUDE.md`) — propose changes, do not silently edit

For these files I state the proposed change, reference the canon value being changed, and wait for Josh's explicit approval.

## Conflict handling

- Existing repo content contradicts a canon: surface, don't silently update
- Existing repo content contradicts prior sessions' work: surface, don't silently revert
- AXIS Protocol version coordination decision unclear: surface to Josh

## Version coordination

The SDK ships its own version cadence; the coupling to AXIS Protocol is a forward dependency only (per Manifest, locked 2026-05-11):

- A new AXIS Protocol minor version (e.g. v0.1 → v0.2) requires the SDK to update to speak the new wire format. The SDK then ships its own version on its own cadence.
- A new SDK version does NOT require protocol-side coordination.
- Pre-1.0 SDK breaking changes between minor versions are permitted (Corporate Canon §License defaults). Patch releases must be additive only.
- Update the [Version Coordination Log](https://www.notion.so/35df359483b281c98747fa47df0b1a65) when shipping or planning a version.

The `SDK_VERSION` constant in `src/index.js` is derived from `package.json` so the two cannot drift.

## Branch and commit hygiene

- Never push to `main`
- Branch names follow conventional-commits style: `<type>/<short-description>` where type is one of `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `style`, `perf`. Do NOT use `claude-code/` or `cowork/` prefixes; do NOT use the session slug as the branch name. (This SDK Project overrides the general Corporate Canon slug-as-branch convention; standardized within the SDK Project 2026-05-12.)
- Slug ≠ branch name. The session slug stays in `~/.claude/sessions/<slug>/`; branches are the public-facing identifier in PRs.
- Conventional commit messages (same prefix vocabulary as branches)
- One conceptual change per commit
- Run `npm test` before opening a PR; new behavior adds tests
- Open a PR against `main`; do not merge yourself

## Code conventions

- ESM only. No CommonJS shim, no transpilation.
- Web Crypto (`crypto.subtle`) for cryptographic operations — works in every target runtime
- `fetch` for network calls — same
- Zero runtime dependencies. Any PR that adds an entry to `dependencies` in `package.json` is rejected unless discussed in an issue first.
- All exported public functions documented with JSDoc
- Ed25519 / EdDSA per RFC 8037 (key algorithm is locked at v0.1; "AIT signing algorithm" appears on the spec's explicit non-changes list)
- Base64url encoding per RFC 4648 §5
- AIT structure per RFC 7519 (JWT)
- All HTTP calls go through `AxisClient._request()` (consistent error mapping, User-Agent header, timeout, error code surface)
- Test files under `test/`, run via `node --test`. New behavior adds tests.

## Session log

At session start, update `~/.claude/sessions/<slug>/ACTIVE.md` with:

- What I'm working on
- Branch I'm using
- Expected output

At session end, update ACTIVE.md plus append to JOURNAL.md and refresh HANDOFF.md per `~/.claude/memory/session_workspace_convention.md`. Mirror ACTIVE state to the Claude Sessions Notion page: https://www.notion.so/35bf359483b281a5b350c3290dc124dc

## Cross-project hygiene

- Items in SDK scope that affect another Project: raise a Coordination database entry; do not silently fix outside this Project's scope.
- Items requiring Josh's decision: leave Status = Open, set Assigned to (Project) = "Josh decision required", explain in Description.
- End every session with a Coordination section in the summary: items resolved, items moved to In progress, items raised, items deferred to Josh.
- If a PR resolves a Coordination item, end-of-session summary includes an explicit "ACTION REQUIRED — Josh to merge" block listing items pending flip.

## When in doubt

Surface to Josh. The canon system's value depends on no session silently improvising.
