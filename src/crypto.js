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
 * Canonicalize a plain object the way the registry expects for proof-of-key
 * ownership: JSON.stringify with top-level keys sorted alphabetically.
 *
 * The registry's /register handler does:
 *   const canonical = JSON.stringify(proofInput, Object.keys(proofInput).sort());
 *
 * This mirrors that exactly so signatures produced here verify there.
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
 * @param {CryptoKey|object} privateKey  Ed25519 private key (CryptoKey or JWK)
 * @param {object} body                  Object to canonicalize + sign
 * @returns {Promise<string>}            base64url-encoded Ed25519 signature
 */
export async function signCanonical(privateKey, body) {
  const key = await _coerceToCryptoKey(privateKey, "signCanonical");
  const canonical = canonicalize(body);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(canonical))
  );
  return b64urlEncode(sig);
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
 * trusted local source. For most cases, use AxisClient.verify() which
 * goes through the registry (the canonical source of truth in AXIS v0.1).
 */
export async function verifyAITLocally(token, publicKeyOrB64) {
  const decoded = decodeAIT(token);
  const { header, payload } = decoded;
  if (header.alg !== "EdDSA") {
    throw new AxisError(ERR.AIT_INVALID, `Unsupported alg: ${header.alg}`);
  }
  if (header.typ !== "AIT") {
    throw new AxisError(ERR.AIT_INVALID, `Unexpected typ: ${header.typ}`);
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new AxisError(ERR.AIT_EXPIRED, "AIT has expired");
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
