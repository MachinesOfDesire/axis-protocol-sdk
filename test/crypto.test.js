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
  const token = await signAIT({
    privateKey: kp.privateKey,
    agentId: "axis:example:bot",
    ttl: -10, // already expired
  });
  await assert.rejects(
    () => verifyAITLocally(token, kp.publicKeyB64),
    (err) => err instanceof AxisError && err.code === ERR.AIT_EXPIRED,
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

test("signCanonical + verify roundtrip matches registry proof format", async () => {
  const kp = await generateKeypair();
  const body = {
    operator: { email: "ops@example.com" },
    publicKey: kp.publicKeyB64,
    metadata: { name: "Mira" },
  };
  const sig = await signCanonical(kp.privateKey, body);

  // Verify the signature matches what the registry would verify.
  // Registry does: verifyEd25519Signature(publicKey, canonical, proofValue)
  // which internally does Ed25519 verify over TextEncoder().encode(canonical).
  const canonical = canonicalize(body);
  const pub = await importPublicKey(kp.publicKeyB64);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(sig),
    new TextEncoder().encode(canonical),
  );
  assert.equal(ok, true);
});

test("importPublicKey rejects keys of wrong length", async () => {
  // Valid-looking base64url but only 16 bytes decoded.
  const short = "AAAAAAAAAAAAAAAAAAAAAA";
  await assert.rejects(
    () => importPublicKey(short),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});
