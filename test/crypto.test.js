/**
 * Unit tests for crypto primitives.
 * Run with: node --test test/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  signAIT,
  decodeAIT,
  verifyAITLocally,
  importPublicKey,
  canonicalize,
  signCanonical,
} from "../src/crypto.js";
import { jcsCanonicalize } from "../src/jcs.js";
import { b64urlDecode } from "../src/base64url.js";
import { AxisError, ERR } from "../src/errors.js";

test("generateKeypair produces 32-byte Ed25519 public key", async () => {
  const kp = await generateKeypair();
  assert.equal(typeof kp.publicKeyB64, "string");
  assert.equal(b64urlDecode(kp.publicKeyB64).length, 32);
  assert.equal(kp.privateKeyJwk.kty, "OKP");
  assert.equal(kp.privateKeyJwk.crv, "Ed25519");
});

test("signAIT produces a valid three-segment JWT", async () => {
  const kp = await generateKeypair();
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    ttl: 300,
    claims: { act: "publish" },
  });
  const parts = token.split(".");
  assert.equal(parts.length, 3);

  const decoded = decodeAIT(token);
  assert.equal(decoded.header.alg, "EdDSA");
  assert.equal(decoded.header.typ, "AIT");
  assert.equal(decoded.header.kid, "axis:example:bot");
  assert.equal(decoded.payload.iss, "axis:example:bot");
  assert.equal(decoded.payload.act, "publish");
  assert.ok(decoded.payload.exp > decoded.payload.iat);
  assert.equal(decoded.payload.exp - decoded.payload.iat, 300);
});

test("verifyAITLocally verifies a token signed with matching key", async () => {
  const kp = await generateKeypair();
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
  });
  const { valid, payload } = await verifyAITLocally(token, kp.publicKeyB64);
  assert.equal(valid, true);
  assert.equal(payload.iss, "axis:example:bot");
});

test("verifyAITLocally rejects a token signed with a different key", async () => {
  const signerKp = await generateKeypair();
  const otherKp = await generateKeypair();
  const token = await signAIT({
    privateKey: signerKp.privateKey,
    agentId: "axis:example:bot",
  });
  const { valid } = await verifyAITLocally(token, otherKp.publicKeyB64);
  assert.equal(valid, false);
});

test("verifyAITLocally rejects an expired token", async () => {
  const kp = await generateKeypair();
  // ttl well outside the 30s clock-skew tolerance
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    ttl: -120,
  });
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64),
    (err) => err instanceof AxisError && err.code === ERR.AIT_EXPIRED,
  );
});

test("verifyAITLocally tolerates small clock skew on exp", async () => {
  const kp = await generateKeypair();
  // 10s past expiry — should be tolerated by default 30s skew
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    ttl: -10,
  });
  const ok = await verifyAITLocally(token, kp.publicKeyB64);
  assert.equal(ok.valid, true);
  // But with skew=0 it should reject
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64, { clockSkew: 0 }),
    (err) => err.code === ERR.AIT_EXPIRED,
  );
});

test("decodeAIT throws on malformed token", () => {
  assert.throws(() => decodeAIT("not-a-jwt"), (err) => err.code === ERR.AIT_INVALID);
  assert.throws(() => decodeAIT("aa.bb"), (err) => err.code === ERR.AIT_INVALID);
  assert.throws(() => decodeAIT(null), (err) => err.code === ERR.AIT_INVALID);
});

test("canonicalize sorts top-level keys deterministically", () => {
  const a = canonicalize({ b: 2, a: 1, c: 3 });
  const b = canonicalize({ c: 3, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"a":1,"b":2,"c":3}');
});

test("canonicalize throws on non-object", () => {
  assert.throws(() => canonicalize("string"), (err) => err.code === ERR.INVALID_INPUT);
  assert.throws(() => canonicalize(null), (err) => err.code === ERR.INVALID_INPUT);
});

test("signCanonical + verify roundtrip matches registry proof format (JCS, v0.3)", async () => {
  const kp = await generateKeypair();
  const body = {
    operator: { email: "ops@example.com" },
    publicKey: kp.publicKeyB64,
    metadata: { name: "Mira" },
  };
  const sig = await signCanonical(kp.privateKey, body);

  // v0.3: signCanonical now canonicalizes with RFC 8785 JCS, matching the
  // registry's verifyCanonicalProof (which tries JCS first). The registry does
  // verifyEd25519Signature(publicKey, jcsCanonicalize(body), proofValue),
  // i.e. Ed25519 verify over TextEncoder().encode(jcsCanonicalize(body)).
  const canonical = jcsCanonicalize(body);
  const pub = await importPublicKey(kp.publicKeyB64);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(sig),
    new TextEncoder().encode(canonical),
  );
  assert.equal(ok, true);

  // Legacy canonicalize would have stripped the nested `metadata.name`, so a
  // verify over the legacy bytes must FAIL — proving we moved off the v0.1 form.
  const legacyOk = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(sig),
    new TextEncoder().encode(canonicalize(body)),
  );
  assert.equal(legacyOk, false);
});

test("importPublicKey rejects keys of wrong length", async () => {
  // Valid-looking base64url but only 16 bytes decoded.
  const short = "AAAAAAAAAAAAAAAAAAAAAA";
  await assert.rejects(
    () => importPublicKey(short),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

// ── Hardening (security-hardening-2026-05-08) ──────────────────────────────

test("verifyAITLocally enforces audience when supplied", async () => {
  const kp = await generateKeypair();
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    claims: { aud: "axis-comments" },
  });
  const ok = await verifyAITLocally(token, kp.publicKeyB64, { audience: "axis-comments" });
  assert.equal(ok.valid, true);
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64, { audience: "other-platform" }),
    (err) => err.code === ERR.AIT_INVALID,
  );
});

test("verifyAITLocally rejects when audience requested but absent from token", async () => {
  const kp = await generateKeypair();
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    // no aud claim
  });
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64, { audience: "axis-comments" }),
    (err) => err.code === ERR.AIT_INVALID,
  );
});

test("verifyAITLocally enforces expectedKid", async () => {
  const kp = await generateKeypair();
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
  });
  const ok = await verifyAITLocally(token, kp.publicKeyB64, { expectedKid: "axis:example:bot" });
  assert.equal(ok.valid, true);
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64, { expectedKid: "axis:other:bot" }),
    (err) => err.code === ERR.AIT_INVALID,
  );
});

test("verifyAITLocally rejects token from the future (iat in future)", async () => {
  const kp = await generateKeypair();
  // Hand-craft a token with iat 10 minutes in the future
  const future = Math.floor(Date.now() / 1000) + 600;
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    claims: { iat: future, exp: future + 300 },
  });
  // Note: signAIT overrides iat/exp — workaround by using ttl trick is unavailable.
  // Test the guard by passing a small clockSkew and a token whose iat we control via claims
  // is not possible with signAIT (it overrides). So instead verify the future-iat path is wired
  // by inspecting the source-level guard via a second check using a non-canonical decode path.
  // Skip strict check here — covered by signAIT-bypass test below.
  const decoded = decodeAIT(token);
  assert.equal(typeof decoded.payload.iat, "number");
  // signAIT spreads `claims` AFTER `iat`/`exp` (see source: `iss, iat, exp, ...claims`),
  // so an iat in claims overrides — this is the right surface to test.
  // Confirm guard rejects:
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64, { clockSkew: 1 }),
    (err) => err.code === ERR.AIT_INVALID || err.code === ERR.AIT_EXPIRED,
  );
});

test("verifyAITLocally rejects when exp is missing and requireExp=true", async () => {
  // Hand-build a token with no exp claim
  const kp = await generateKeypair();
  const headerB64 = btoa(JSON.stringify({ alg: "EdDSA", typ: "AIT", kid: "axis:e:b" }))
    .replace(/[+/]/g, (c) => ({ "+": "-", "/": "_" })[c])
    .replace(/=+$/g, "");
  const payloadB64 = btoa(JSON.stringify({ iss: "axis:e:b", iat: Math.floor(Date.now() / 1000) }))
    .replace(/[+/]/g, (c) => ({ "+": "-", "/": "_" })[c])
    .replace(/=+$/g, "");
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode(signingInput)),
  );
  // base64url encode signature
  let s = "";
  for (let i = 0; i < sig.length; i++) s += String.fromCharCode(sig[i]);
  const sigB64 = btoa(s).replace(/[+/]/g, (c) => ({ "+": "-", "/": "_" })[c]).replace(/=+$/g, "");
  const token = `${signingInput}.${sigB64}`;
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64),
    (err) => err.code === ERR.AIT_INVALID,
  );
  // Opt-out works:
  const ok = await verifyAITLocally(token, kp.publicKeyB64, { requireExp: false });
  assert.equal(ok.valid, true);
});

// ────────────────────────────────────────────────────────────────────────────
// Security review 2026-05-08/09 — S-M1: robust private-key detection
// ────────────────────────────────────────────────────────────────────────────

test("S-M1: signAIT accepts a JWK", async () => {
  const kp = await generateKeypair();
  const ait = await signAIT({
    privateKey: kp.privateKeyJwk,
    agentId: "axis:op:agent",
    ttl: 60,
  });
  assert.match(ait, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
});

test("S-M1: signAIT accepts a CryptoKey", async () => {
  const kp = await generateKeypair();
  const ait = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:op:agent",
    ttl: 60,
  });
  assert.match(ait, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
});

test("S-M1: signAIT rejects null/undefined private key", async () => {
  await assert.rejects(
    () => signAIT({ privateKey: null, agentId: "axis:op:agent" }),
    (err) => err.code === ERR.INVALID_INPUT && /privateKey is required/i.test(err.message),
  );
  await assert.rejects(
    () => signAIT({ privateKey: undefined, agentId: "axis:op:agent" }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("S-M1: signAIT rejects an object that is neither a JWK nor a CryptoKey", async () => {
  await assert.rejects(
    () => signAIT({ privateKey: { random: "stuff", noKty: true }, agentId: "axis:op:agent" }),
    (err) => err.code === ERR.INVALID_INPUT && /CryptoKey or a JWK/i.test(err.message),
  );
});

test("S-M1: signCanonical accepts JWK and CryptoKey symmetrically", async () => {
  const kp = await generateKeypair();
  const body = { a: 1, b: 2 };
  const sigFromJwk = await signCanonical(kp.privateKeyJwk, body);
  const sigFromKey = await signCanonical(kp.privateKey, body);
  assert.equal(sigFromJwk, sigFromKey, "both detection paths should sign identically");
});
