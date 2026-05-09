# axis-protocol-sdk

Reference SDK for the **AXIS protocol**. Agent identity, signing, and registry operations in one small library. Zero runtime dependencies, ESM, runs in Node 20+, Cloudflare Workers, Deno, Bun, and modern browsers.

> **Status:** v0.2.2 (the constant `SDK_VERSION` is derived from `package.json` so the two cannot drift). The protocol itself is v0.1.1 (Apache 2.0) at [MachinesOfDesire/axis-protocol](https://github.com/MachinesOfDesire/axis-protocol). Breaking changes are possible before v1. See [`CHANGELOG.md`](./CHANGELOG.md) for release notes.

---

## What this does

The AXIS reference registry is a small HTTP API. Anything that wants to *use* AXIS needs to know how to generate Ed25519 keypairs in the right format, sign AITs the registry will accept, verify tokens, register agents, and issue or revoke delegations. This SDK is the canonical client for all of that.

Without it, every consumer would re-implement the primitives (and do it slightly differently). With it, you write `client.createAgent(...)` and `await session.sign()` and the protocol stays consistent.

## Properties

- **Zero runtime dependencies.** Uses only `crypto.subtle`, `fetch`, `TextEncoder`, and base64 helpers. All built-in in every target runtime.
- **Universal.** Same source runs in Node 20+, Cloudflare Workers, Deno, Bun, and modern browsers.
- **ESM-only.** No CommonJS shim, no transpilation.
- **Small.** Under 1000 lines of hand-written source.

## Install

```bash
npm install axis-protocol-sdk
```

Or, before publication, point at a local checkout:

```bash
npm install /path/to/axis-protocol-sdk
```

## Quick tour

### Verify an AIT (public, no auth)

```js
import { AxisClient } from "axis-protocol-sdk";

const client = new AxisClient({ registryUrl: "https://registry.axisprime.ai" });

const result = await client.verifyAIT(tokenFromIncomingRequest);
if (!result.valid) {
  throw new Error(`Invalid token: ${result.error}`);
}
console.log(result.agent_id, result.operator_id, result.status, result.expires_at);
```

### Register an agent and sign tokens

```js
import { AxisClient } from "axis-protocol-sdk";

const registrar = new AxisClient({
  registryUrl: "https://registry.axisprime.ai",
  apiKey: process.env.AXIS_REGISTRAR_KEY,
});

// Generate a keypair, register, and get a session with a sign() helper.
const session = await registrar.createAgent({
  operator: { email: "ops@example.com" },
  metadata: { name: "Mira", description: "Managing editor for Offworld News" },
});

console.log("agent_id:", session.agent_id);
console.log("did:", session.did);

// Sign a short-lived AIT with an application claim.
const ait = await session.sign({ ttl: 300, claims: { act: "publish" } });
```

### Verify locally without hitting the registry

```js
import { verifyAITLocally } from "axis-protocol-sdk";

const { valid, payload } = await verifyAITLocally(token, knownPublicKeyB64, {
  audience: "your-platform-id",     // require token.aud to match (recommended)
  expectedKid: "axis:op:agent",     // require header.kid to match (recommended)
  // requireExp: true,              // default — reject tokens without exp
  // clockSkew: 30,                 // default — seconds of tolerance on exp/iat/nbf
});
if (valid) console.log("Issued by:", payload.iss);
```

Use this when you already have the agent's public key from a trusted local source. For anything public-facing, prefer `client.verifyAIT()`, which consults the registry (the canonical source of truth in AXIS v0.1).

The third options argument was added in v0.2.2; existing 0.2.1 callers (`verifyAITLocally(token, key)`) keep working unchanged. See [`CHANGELOG.md`](./CHANGELOG.md) for the full migration note.

## Client API, by role

The same `AxisClient` handles every role of caller. If the API key is missing or insufficient for a given endpoint, the server returns 401 / 403 and the SDK throws an `AxisError` with a stable `code`.

### Public (no `apiKey` needed)

| Method | Endpoint |
|---|---|
| `getAccessPolicy()` | GET `/.well-known/axis-access` |
| `resolveAgent(id)` | GET `/agents/:id` |
| `resolveDid(did)` | GET `/resolve/:did` |
| `getOperator(id)` | GET `/operators/:id` |
| `verifyAIT(token)` | GET `/verify?token=` |
| `verifyDid(did)` | GET `/verify/:did` |
| `verifySignature(opts)` | POST `/verify/signature` |
| `checkRevocation(id)` | GET `/revocation/:id` |
| `getDelegation(id)` | GET `/delegations/:id` |
| `verifyDelegationChain(id)` | GET `/delegations/:id/chain` |

### Registrar (`apiKey` required)

| Method | Endpoint |
|---|---|
| `registerAgent({operator, publicKey, metadata, service, proof})` | POST `/register` |
| `deactivateAgent(id, {reason})` | DELETE `/agents/:id` |
| `listAgents({operator_id})` | GET `/agents?operator_id=` |
| `createDelegation({issued_by, issued_to, root_operator, scope, expires, constraints?, parent_credential_id?, signature?})` | POST `/delegations` |
| `revokeDelegation(id, {reason})` | DELETE `/delegations/:id` |
| `verifyDomain({email, domain, method})` | POST `/operators/verify-domain` |
| `checkDomain({domain, token})` | POST `/operators/verify-domain/check` |
| `createAgent({operator, metadata, service})` | POST `/register` (convenience: keypair + register + sign helper) |

### Admin / super-admin (role enforced server-side)

| Method | Endpoint | Role |
|---|---|---|
| `adminListOperators({limit, offset})` | GET `/admin/operators` | admin+ |
| `adminGetAgent(id)` | GET `/admin/agents/:id` | admin+ |
| `adminListAgents({limit, offset, status})` | GET `/admin/agents` | admin+ |
| `adminAudit({limit, offset})` | GET `/admin/audit` | admin+ |
| `adminStats()` | GET `/admin/stats` | admin+ |
| `forceDeactivateAgent(id, {reason})` | POST `/admin/force-deactivate-agent/:id` | super_admin |
| `forceRevokeDelegation(id, {reason})` | POST `/admin/force-revoke-delegation/:id` | super_admin |

Break-glass endpoints require a non-empty `reason` string. The registry writes an audit row *before* the mutation and aborts if the audit write fails.

## Error handling

Every call that touches the registry throws `AxisError` on failure, except `verifyAIT()` which returns `{valid: false, error}` for invalid tokens (so the common case does not need a try/catch around a known-bad token).

```js
import { AxisError, ERR } from "axis-protocol-sdk";

try {
  await client.deactivateAgent("axis:other-operator:bot");
} catch (err) {
  if (err instanceof AxisError && err.code === ERR.NOT_YOUR_RESOURCE) {
    console.log("That agent belongs to a different registrar");
  } else {
    throw err;
  }
}
```

Stable error codes on `err.code`:

- `REGISTRY_UNREACHABLE`, `REGISTRY_HTTP` — transport
- `API_KEY_REQUIRED`, `UNAUTHORIZED`, `FORBIDDEN`, `INSUFFICIENT_ROLE`, `NOT_YOUR_RESOURCE` — auth / authorization
- `INVALID_INPUT`, `NOT_FOUND`, `CONFLICT` — request state
- `AIT_INVALID`, `AIT_EXPIRED` — token state
- `AGENT_NOT_FOUND`, `AGENT_REVOKED` — agent state

## Crypto helpers

Exported from the top level, usable standalone:

```js
import {
  generateKeypair,       // {publicKey, privateKey, publicKeyB64, privateKeyJwk}
  signAIT,               // builds a compact JWT-encoded AIT
  decodeAIT,             // parses without verifying
  verifyAITLocally,      // verifies against a known public key
  importPrivateKey,      // JWK -> CryptoKey
  importPublicKey,       // base64url raw -> CryptoKey
  canonicalize,          // object -> canonical JSON (sorted top-level keys)
  signCanonical,         // sign a canonical-encoded object (used for register proof)
} from "axis-protocol-sdk";
```

## Examples

See [`examples/`](./examples/):

- [`verify-incoming.js`](./examples/verify-incoming.js) — verify an AIT on an incoming HTTP request
- [`register-and-sign.js`](./examples/register-and-sign.js) — register an agent, then sign tokens
- [`ghost-commenter.md`](./examples/ghost-commenter.md) — how Offworld News uses the SDK for Ghost comments

## Development

```bash
npm test        # runs all unit tests
```

No build step. The source IS the published artifact.

## License

Apache 2.0. See [LICENSE](./LICENSE).
