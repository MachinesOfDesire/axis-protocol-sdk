/**
 * AXIS crypto primitives — pure, no network.
 *
 * Uses the platform-native WebCrypto API (`crypto.subtle`), which is
 * available as a global in:
 *   - Node 20+ (Node 19+ exposed it as a global)
 *   - Cloudflare Workers
 *   - Modern browsers
 *
 * Algorithm: Ed25519 (the only signing algorithm AXIS v0.1 supports).
 */

import { b64urlEncode, b64urlDecode, b64urlDecodeString } from "./base64url.js";
import { AxisError, ERR } from "./errors.js";
import { jcsCanonicalize } from "./jcs.js";

/**
 * Generate a fresh Ed25519 keypair for an AXIS agent (or operator).
 *
 * Returns the raw CryptoKey objects (for in-memory use), plus serialized
 * forms ready to be sent over the wire (publicKeyB64) or persisted (privateKeyJwk).
 */
export async function generateKeypair() {
  const keys = await crypto.subtle.generateKey(
    { name: "Ed25519", namedCurve: "Ed25519" },
    true,
    ["sign", "verify"]
  );
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const privJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    publicKeyB64: b64urlEncode(pubRaw),
    privateKeyJwk: privJwk,
  };
}

/**
 * Import an Ed25519 private key from a JWK (the format produced by generateKeypair).
 */
export async function importPrivateKey(privateKeyJwk) {
  return crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "Ed25519", namedCurve: "Ed25519" },
    false,
    ["sign"]
  );
}

/**
 * Import an Ed25519 public key from a base64url-encoded raw 32-byte key.
 */
export async function importPublicKey(publicKeyB64) {
  const bytes = b64urlDecode(publicKeyB64);
  if (bytes.length !== 32) {
    throw new AxisError(ERR.INVALID_INPUT, "Ed25519 public keys must be exactly 32 bytes");
  }
  return crypto.subtle.importKey(
    "raw",
    bytes,
    { name: "Ed25519", namedCurve: "Ed25519" },
    false,
    ["verify"]
  );
}

/**
 * Sign an AXIS Identity Token (AIT).
 *
 * AIT is a JWT signed with Ed25519. Header carries `alg: EdDSA`, `typ: AIT`,
 * `kid: <agent_id>`. Payload carries `iss`, `iat`, `exp`, plus optional
 * application-specific claims.
 *
 * @param {object} opts
 * @param {CryptoKey|object} opts.privateKey  CryptoKey or JWK
 * @param {string} opts.agentId               Full AXIS agent ID
 * @param {number} [opts.ttl=300]             Lifetime in seconds
 * @param {object} [opts.claims]              Extra payload claims to merge in
 * @returns {Promise<string>}                 The compact JWT-encoded AIT
 */
export async function signAIT({ privateKey, agentId, ttl = 300, claims = {} }) {
  if (!agentId) throw new AxisError(ERR.INVALID_INPUT, "signAIT: agentId is required");
  const key = await _coerceToCryptoKey(privateKey, "signAIT");

  const header = { alg: "EdDSA", typ: "AIT", kid: agentId };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: agentId,
    iat: now,
    exp: now + ttl,
    ...claims,
  };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(signingInput))
  );
  return `${signingInput}.${b64urlEncode(sig)}`;
}

/**
 * Coerce a private-key input to a CryptoKey usable by `crypto.subtle.sign`.
 * Accepts either:
 *   - a CryptoKey directly (used as-is)
 *   - a JWK object (imported via importPrivateKey)
 *
 * S-M1: detection no longer relies on the absence of the `type` property
 * (Object.prototype could have one in unusual environments, and CryptoKey
 * also has a `type` getter, so `!("type" in privateKey)` was both a false-
 * positive risk and a footgun). Detection now checks the JWK-defining `kty`
 * property and uses `instanceof CryptoKey` (when the global is available)
 * as the positive identity test.
 *
 * @param {CryptoKey|object} privateKey  Ed25519 private key (CryptoKey or JWK)
 * @param {string} caller                 Function name, for error messages
 * @returns {Promise<CryptoKey>}
 */
async function _coerceToCryptoKey(privateKey, caller) {
  if (!privateKey) {
    throw new AxisError(ERR.INVALID_INPUT, `${caller}: privateKey is required`);
  }
  // CryptoKey path. `instanceof CryptoKey` works in Node 20+, browsers, and
  // Cloudflare Workers. If the global is absent (some non-standard host),
  // fall back to a duck-typed check on `algorithm` + `type` getters.
  if (typeof CryptoKey !== "undefined" && privateKey instanceof CryptoKey) {
    return privateKey;
  }
  if (
    typeof privateKey === "object" &&
    typeof privateKey.algorithm === "object" &&
    typeof privateKey.type === "string" &&
    typeof privateKey.extractable === "boolean"
  ) {
    return privateKey;
  }
  // JWK path. RFC 7517 §4.1: `kty` is REQUIRED on every JWK. For Ed25519
  // it's "OKP" (RFC 8037 §2).
  if (typeof privateKey === "object" && typeof privateKey.kty === "string") {
    return importPrivateKey(privateKey);
  }
  throw new AxisError(
    ERR.INVALID_INPUT,
    `${caller}: privateKey must be a CryptoKey or a JWK with a kty field`
  );
}

/**
 * @deprecated LEGACY v0.1 canonicalization. Superseded by RFC 8785 JCS
 * (`jcsCanonicalize` in ./jcs.js) as of AXIS Protocol v0.2 §6.1 / SDK v0.3.
 * Kept exported ONLY so callers that still need to reproduce a pre-JCS
 * signature (e.g. to re-verify an old legacy proof) can do so. Do NOT use for
 * new signing — `signCanonical` now uses JCS.
 *
 * Canonicalize a plain object the v0.1 way: JSON.stringify with top-level keys
 * sorted alphabetically.
 *
 *   JSON.stringify(obj, Object.keys(obj).sort())
 *
 * ⚠️ Footgun (the reason v0.2 moved to JCS): the second argument to
 * JSON.stringify, when an array, is a REPLACER that *filters which keys appear
 * at every nesting level*. It does NOT recursively sort nested object keys.
 * Two consequences:
 *
 *   1. Nested object keys appear in source-iteration order (V8: insertion-
 *      order for string keys), not sorted order. Two clients that build the
 *      same conceptual object with different key insertion orders inside a
 *      nested field produce different canonical bytes and different
 *      signatures.
 *   2. Any nested key whose name does NOT also appear at the top level is
 *      stripped entirely. e.g. canonicalize({a: 1, b: {c: 2}}) yields
 *      '{"a":1,"b":{}}' — the inner `c` is filtered out because `c` isn't
 *      in the top-level key list.
 *
 * The registry still accepts legacy proofs (proofType absent) for back-compat,
 * but verifies JCS first. New proofs should be JCS.
 */
export function canonicalize(obj) {
  if (!obj || typeof obj !== "object") {
    throw new AxisError(ERR.INVALID_INPUT, "canonicalize: expected an object");
  }
  return JSON.stringify(obj, Object.keys(obj).sort());
}

/**
 * Sign a canonical-encoded body and return a base64url signature string.
 * Used for the `proof.proofValue` field on agent registration.
 *
 * As of SDK v0.3 / AXIS Protocol v0.2 §6.1 this canonicalizes with RFC 8785
 * JCS (`jcsCanonicalize`), NOT the legacy top-level-sort `canonicalize`. The
 * registry's verifyCanonicalProof tries JCS first, so this signature verifies
 * there whether or not the wire proof carries `proofType: "jcs-eddsa-2026"`.
 * Callers SHOULD send the proof with that proofType (see AxisClient.createAgent)
 * so the registry takes the JCS path explicitly rather than the legacy
 * fall-through.
 *
 * @param {CryptoKey|object} privateKey  Ed25519 private key (CryptoKey or JWK)
 * @param {object} body                  Object to canonicalize + sign
 * @returns {Promise<string>}            base64url-encoded Ed25519 signature
 */
export async function signCanonical(privateKey, body) {
  const key = await _coerceToCryptoKey(privateKey, "signCanonical");
  const canonical = jcsCanonicalize(body);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(canonical))
  );
  return b64urlEncode(sig);
}

/**
 * Sign a DelegationCredential (DC) document — Option A, AXIS Protocol v0.2
 * §4.4 / §8. The issuer signs the RFC 8785 JCS canonicalization of the
 * complete DC document MINUS its `proof` field, with Ed25519. Returns the DC
 * with a W3C Data-Integrity proof envelope attached.
 *
 * The bytes signed are `jcsCanonicalize(dc)` where `dc` is passed WITHOUT a
 * proof field — exactly what the registry's verifyDelegationProof recomputes
 * (it strips `proof` then JCS-canonicalizes), so the proofValue verifies there
 * byte-for-byte. Mirrors the registry's buildSignedDelegation test helper.
 *
 * @param {CryptoKey|object} privateKey  Issuer's Ed25519 private key (CryptoKey or JWK)
 * @param {object} dc                    DC document fields, WITHOUT a `proof` field.
 *                                       Must include `issued_by` (used for verificationMethod).
 * @returns {Promise<object>}            `{ ...dc, proof: { ... } }`
 */
export async function signDelegation(privateKey, dc) {
  if (!dc || typeof dc !== "object") {
    throw new AxisError(ERR.INVALID_INPUT, "signDelegation: dc must be an object");
  }
  if (!dc.issued_by) {
    throw new AxisError(ERR.INVALID_INPUT, "signDelegation: dc.issued_by is required (used for verificationMethod)");
  }
  if ("proof" in dc) {
    throw new AxisError(ERR.INVALID_INPUT, "signDelegation: dc must NOT already carry a proof field");
  }
  const key = await _coerceToCryptoKey(privateKey, "signDelegation");
  const canonical = jcsCanonicalize(dc);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(canonical))
  );
  const proofValue = b64urlEncode(sig);
  return {
    ...dc,
    proof: {
      type: "Ed25519Signature2020",
      proofType: "jcs-eddsa-2026",
      verificationMethod: `${dc.issued_by}#key-1`,
      proofPurpose: "assertionMethod",
      proofValue,
    },
  };
}

/**
 * Decode an AIT into header + payload + signature parts WITHOUT verifying.
 * Useful for inspecting a token's claims before deciding whether to call
 * a registry. Throws if the structural shape is wrong.
 */
export function decodeAIT(token) {
  if (typeof token !== "string") {
    throw new AxisError(ERR.AIT_INVALID, "decodeAIT: token must be a string");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new AxisError(ERR.AIT_INVALID, "decodeAIT: token must have three segments");
  }
  let header, payload, signature;
  try {
    header = JSON.parse(b64urlDecodeString(parts[0]));
    payload = JSON.parse(b64urlDecodeString(parts[1]));
    signature = b64urlDecode(parts[2]);
  } catch (e) {
    throw new AxisError(ERR.AIT_INVALID, `decodeAIT: malformed segments: ${e.message}`, { cause: e });
  }
  return { header, payload, signature, raw: token };
}

/**
 * Locally verify an AIT against a known public key — does NOT consult the
 * registry. Use this only when you have the agent's public key from a
 * trusted local source. For most cases, use AxisClient.verifyAIT() which
 * goes through the registry (the canonical source of truth in AXIS v0.1).
 *
 * @param {string} token                   The compact JWT-encoded AIT.
 * @param {CryptoKey|string} publicKeyOrB64  Trusted Ed25519 public key.
 * @param {object} [opts]
 * @param {string} [opts.audience]         If provided, require payload.aud to match (string equality).
 *                                         AXIS v0.2 will likely require this; pass it whenever your
 *                                         platform has a stable identifier so a token minted for
 *                                         platform A can't be replayed against platform B.
 * @param {string} [opts.expectedKid]      If provided, require header.kid to match. Use this to defend
 *                                         against the footgun where the caller passes the wrong public
 *                                         key for a given kid — without this check, the signature
 *                                         verifies against whatever key you supplied even if it's not
 *                                         the kid's key.
 * @param {boolean} [opts.requireExp=true] Reject tokens without an `exp` claim. Default is true; pass
 *                                         false only if you have a deliberate reason (e.g. legacy tokens).
 * @param {number} [opts.clockSkew=30]     Allowed clock skew in seconds for exp/iat/nbf checks.
 * @returns {Promise<{valid: boolean, header: object, payload: object, reason?: string}>}
 *
 * Backward compatibility: existing callers `verifyAITLocally(token, key)` continue to work. The
 * function now also rejects `iat` claims more than `clockSkew` seconds in the future and validates
 * an optional `nbf` claim.
 */
export async function verifyAITLocally(token, publicKeyOrB64, opts = {}) {
  const { audience, expectedKid, requireExp = true, clockSkew = 30 } = opts;
  const decoded = decodeAIT(token);
  const { header, payload } = decoded;
  if (header.alg !== "EdDSA") {
    throw new AxisError(ERR.AIT_INVALID, `Unsupported alg: ${header.alg}`);
  }
  if (header.typ !== "AIT") {
    throw new AxisError(ERR.AIT_INVALID, `Unexpected typ: ${header.typ}`);
  }
  if (expectedKid && header.kid !== expectedKid) {
    throw new AxisError(
      ERR.AIT_INVALID,
      `kid mismatch: expected ${expectedKid}, got ${header.kid}`,
    );
  }
  const now = Math.floor(Date.now() / 1000);
  if (requireExp && typeof payload.exp !== "number") {
    throw new AxisError(ERR.AIT_INVALID, "AIT is missing required `exp` claim");
  }
  if (typeof payload.exp === "number" && payload.exp + clockSkew < now) {
    throw new AxisError(ERR.AIT_EXPIRED, "AIT has expired");
  }
  if (typeof payload.iat === "number" && payload.iat > now + clockSkew) {
    throw new AxisError(ERR.AIT_INVALID, "AIT `iat` is in the future");
  }
  if (typeof payload.nbf === "number" && payload.nbf > now + clockSkew) {
    throw new AxisError(ERR.AIT_INVALID, "AIT `nbf` not yet reached");
  }
  if (audience !== undefined && payload.aud !== audience) {
    throw new AxisError(
      ERR.AIT_INVALID,
      `AIT audience mismatch: expected ${audience}, got ${payload.aud ?? "(none)"}`,
    );
  }
  let key = publicKeyOrB64;
  if (typeof publicKeyOrB64 === "string") {
    key = await importPublicKey(publicKeyOrB64);
  }
  const parts = token.split(".");
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const sig = b64urlDecode(parts[2]);
  const ok = await crypto.subtle.verify("Ed25519", key, sig, signingInput);
  return { valid: ok, header, payload };
}
