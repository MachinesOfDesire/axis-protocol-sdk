/**
 * Unit tests for the RFC 8785 JCS canonicalizer (src/jcs.js) and the
 * JCS-based signers in src/crypto.js (signDelegation + the JCS-upgraded
 * signCanonical registration proof).
 *
 * The JCS exact-byte vectors are ported from the registry's test/jcs.test.js
 * (the source of truth for the wire byte format), including the
 * nested-key-survival regression that motivated the v0.1 → v0.2 move.
 *
 * Run with: node --test test/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { jcsCanonicalize, jcsCanonicalizeBytes } from "../src/jcs.js";
import {
  generateKeypair,
  signDelegation,
  signCanonical,
  importPublicKey,
} from "../src/crypto.js";
import { b64urlDecode } from "../src/base64url.js";
import { AxisError, ERR } from "../src/errors.js";

// ── JCS exact-byte vectors (ported from axis-registry test/jcs.test.js) ──────

test("recursively sorts object keys at every nesting level", () => {
  assert.equal(
    jcsCanonicalize({ b: { d: 1, c: 2 }, a: 3 }),
    '{"a":3,"b":{"c":2,"d":1}}'
  );
});

test("REGRESSION: nested keys survive (v0.1 top-level-sort would strip them)", () => {
  // Legacy JSON.stringify(obj, Object.keys(obj).sort()) yields '{"a":1,"b":{}}'
  // because `c` is not a top-level key. JCS must keep the inner value.
  assert.equal(jcsCanonicalize({ a: 1, b: { c: 2 } }), '{"a":1,"b":{"c":2}}');
});

test("insertion order does not affect output (determinism)", () => {
  assert.equal(
    jcsCanonicalize({ a: 1, b: 2, nested: { y: 1, x: 2 } }),
    jcsCanonicalize({ nested: { x: 2, y: 1 }, b: 2, a: 1 })
  );
});

test("array element order is preserved, not sorted", () => {
  assert.equal(jcsCanonicalize({ z: [3, 1, 2] }), '{"z":[3,1,2]}');
});

test("canonicalizes a top-level array of objects", () => {
  assert.equal(jcsCanonicalize([{ b: 1, a: 2 }]), '[{"a":2,"b":1}]');
});

test("keys sort by UTF-16 code unit, not numeric value", () => {
  // "1" < "10" < "2" lexicographically. A numeric sort would give 1,2,10.
  assert.equal(jcsCanonicalize({ 10: 0, 2: 0, 1: 0 }), '{"1":0,"10":0,"2":0}');
});

test("number serialization matches ECMAScript Number::toString", () => {
  assert.equal(jcsCanonicalize({ n: 4.5 }), '{"n":4.5}');
  assert.equal(jcsCanonicalize({ n: 1e30 }), '{"n":1e+30}');
  assert.equal(jcsCanonicalize({ n: 2e-3 }), '{"n":0.002}');
  assert.equal(jcsCanonicalize({ n: 0 }), '{"n":0}');
  assert.equal(jcsCanonicalize({ n: -1 }), '{"n":-1}');
});

test("string escaping matches JSON (control chars escaped, slash not)", () => {
  assert.equal(jcsCanonicalize({ s: "\n" }), '{"s":"\\n"}');
  assert.equal(jcsCanonicalize({ s: "a/b" }), '{"s":"a/b"}');
  assert.equal(jcsCanonicalize({ s: '"\\' }), '{"s":"\\"\\\\"}');
});

test("omits undefined-valued object members (JSON semantics)", () => {
  assert.equal(jcsCanonicalize({ a: 1, b: undefined, c: 3 }), '{"a":1,"c":3}');
});

test("preserves null in objects and arrays", () => {
  assert.equal(jcsCanonicalize({ a: null }), '{"a":null}');
  assert.equal(jcsCanonicalize([null, true, false]), "[null,true,false]");
});

test("rejects non-finite numbers (no JCS representation)", () => {
  assert.throws(() => jcsCanonicalize({ n: NaN }), TypeError);
  assert.throws(() => jcsCanonicalize({ n: Infinity }), TypeError);
  assert.throws(() => jcsCanonicalize(-Infinity), TypeError);
});

test("jcsCanonicalizeBytes returns UTF-8 bytes of the canonical string", () => {
  const bytes = jcsCanonicalizeBytes({ b: 1, a: 2 });
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(new TextDecoder().decode(bytes), '{"a":2,"b":1}');
});

test("handles non-ASCII without escaping (per RFC 8785 / JSON)", () => {
  assert.equal(jcsCanonicalize({ s: "€" }), '{"s":"€"}');
});

// ── signDelegation round-trip (independent verification) ─────────────────────

/** A representative DC document (no proof field), shaped per AXIS v0.2 §4.4. */
function sampleDc(issuedBy) {
  return {
    issued_by: issuedBy,
    issued_to: "axis:acme:worker",
    root_operator: issuedBy,
    scope: ["read:comments", "write:comments"],
    expires: "2027-01-01T00:00:00.000Z",
    constraints: { max_calls: 100, nested: { z: 1, a: 2 } },
  };
}

test("signDelegation emits the v0.2 Data-Integrity proof envelope", async () => {
  const kp = await generateKeypair();
  const issuedBy = "axis:acme:operator";
  const dc = sampleDc(issuedBy);
  const signed = await signDelegation(kp.privateKey, dc);

  // Original fields preserved, proof appended.
  assert.equal(signed.issued_by, issuedBy);
  assert.deepEqual(signed.scope, dc.scope);
  assert.equal(signed.proof.type, "Ed25519Signature2020");
  assert.equal(signed.proof.proofType, "jcs-eddsa-2026");
  assert.equal(signed.proof.verificationMethod, `${issuedBy}#key-1`);
  assert.equal(signed.proof.proofPurpose, "assertionMethod");
  assert.equal(typeof signed.proof.proofValue, "string");
});

test("signDelegation round-trip: independent verify of JCS(dc-without-proof)", async () => {
  const kp = await generateKeypair();
  const dc = sampleDc("axis:acme:operator");
  const signed = await signDelegation(kp.privateKey, dc);

  // Independently reconstruct what the registry's verifyDelegationProof does:
  // strip `proof`, JCS-canonicalize, Ed25519-verify the proofValue.
  const payload = { ...signed };
  delete payload.proof;
  const canonical = jcsCanonicalize(payload);
  const pub = await importPublicKey(kp.publicKeyB64);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(signed.proof.proofValue),
    new TextEncoder().encode(canonical),
  );
  assert.equal(ok, true);

  // And the stripped payload must equal the original dc byte-for-byte under JCS
  // (no proof leakage into the signed bytes).
  assert.equal(canonical, jcsCanonicalize(dc));
});

test("signDelegation: tampering the DC after signing fails verification", async () => {
  const kp = await generateKeypair();
  const signed = await signDelegation(kp.privateKey, sampleDc("axis:acme:operator"));

  // Mutate a signed field, re-canonicalize, verify against the original sig.
  const tampered = { ...signed, scope: ["admin:*"] };
  delete tampered.proof;
  const pub = await importPublicKey(kp.publicKeyB64);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(signed.proof.proofValue),
    new TextEncoder().encode(jcsCanonicalize(tampered)),
  );
  assert.equal(ok, false);
});

test("signDelegation accepts a JWK and a CryptoKey symmetrically", async () => {
  const kp = await generateKeypair();
  const dc = sampleDc("axis:acme:operator");
  const fromJwk = await signDelegation(kp.privateKeyJwk, dc);
  const fromKey = await signDelegation(kp.privateKey, dc);
  // Ed25519 is deterministic, so the same key over the same bytes → same sig.
  assert.equal(fromJwk.proof.proofValue, fromKey.proof.proofValue);
});

test("signDelegation rejects a dc that already carries a proof", async () => {
  const kp = await generateKeypair();
  const dc = { ...sampleDc("axis:acme:operator"), proof: { proofValue: "x" } };
  await assert.rejects(
    () => signDelegation(kp.privateKey, dc),
    (err) => err instanceof AxisError && err.code === ERR.INVALID_INPUT,
  );
});

test("signDelegation requires issued_by", async () => {
  const kp = await generateKeypair();
  const { issued_by, ...rest } = sampleDc("axis:acme:operator");
  void issued_by;
  await assert.rejects(
    () => signDelegation(kp.privateKey, rest),
    (err) => err instanceof AxisError && err.code === ERR.INVALID_INPUT,
  );
});

// ── Registration proof is now JCS (signCanonical) ────────────────────────────

test("signCanonical now produces a JCS signature (round-trips against jcsCanonicalize)", async () => {
  const kp = await generateKeypair();
  // A body with a NESTED object whose inner key is not a top-level key — the
  // exact case the legacy canonicalize would have stripped. Under JCS it must
  // survive, and the signature must verify over the JCS bytes.
  const body = {
    operator: { email: "ops@example.com" },
    publicKey: kp.publicKeyB64,
    metadata: { name: "Mira" },
  };
  const sig = await signCanonical(kp.privateKey, body);

  const canonical = jcsCanonicalize(body);
  const pub = await importPublicKey(kp.publicKeyB64);
  const ok = await crypto.subtle.verify(
    "Ed25519",
    pub,
    b64urlDecode(sig),
    new TextEncoder().encode(canonical),
  );
  assert.equal(ok, true);

  // Confirm it is JCS, not the legacy top-level sort: the nested `name` would
  // have been stripped by legacy canonicalize, producing different bytes and a
  // signature that does NOT verify over the JCS canonicalization.
  assert.equal(canonical, '{"metadata":{"name":"Mira"},"operator":{"email":"ops@example.com"},"publicKey":"' + kp.publicKeyB64 + '"}');
});
