/**
 * Unit tests for AxisClient — uses a fake fetch that records requests
 * and returns programmed responses. No network calls.
 * Run with: node --test test/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { AxisClient } from "../src/client.js";
import { AxisError, ERR } from "../src/errors.js";

/** Build a fake fetch that records calls and returns the next programmed response. */
function makeFakeFetch(responses) {
  const queue = [...responses];
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", headers: init.headers || {}, body: init.body });
    const next = queue.shift();
    if (!next) throw new Error(`fake fetch: no more responses queued (call ${calls.length})`);
    if (next.throws) throw next.throws;
    const status = next.status ?? 200;
    const bodyObj = next.body ?? {};
    return {
      ok: status >= 200 && status < 300,
      status,
      async json() {
        return bodyObj;
      },
    };
  };
  return { fetchImpl, calls };
}

// ── Construction ──────────────────────────────────────────────────────────

test("constructor requires registryUrl", () => {
  assert.throws(() => new AxisClient({}), (err) => err.code === ERR.INVALID_INPUT);
});

test("constructor trims trailing slash from registryUrl", () => {
  const c = new AxisClient({ registryUrl: "https://r.example.com/" });
  assert.equal(c.registryUrl, "https://r.example.com");
});

// ── Public endpoints ──────────────────────────────────────────────────────

test("resolveAgent GETs /agents/:slug and strips axis: prefix", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ body: { agent_id: "bot" } }]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await c.resolveAgent("axis:example:bot");
  assert.equal(calls[0].url, "https://r/agents/bot");
});

test("resolveDid strips did: correctly in URL encoding", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ body: {} }]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await c.resolveDid("did:axis:prime:bot");
  assert.equal(calls[0].url, "https://r/resolve/did%3Aaxis%3Aprime%3Abot");
});

test("getOperator requires operatorId", async () => {
  const c = new AxisClient({ registryUrl: "https://r" });
  await assert.rejects(() => c.getOperator(), (err) => err.code === ERR.INVALID_INPUT);
});

test("verifyAIT returns {valid:false} on bad token without throwing", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 200, body: { valid: false, error: "expired" } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  const r = await c.verifyAIT("some-token");
  assert.equal(r.valid, false);
  assert.equal(r.error, "expired");
});

test("verifyAIT returns valid=true payload on success", async () => {
  const { fetchImpl } = makeFakeFetch([
    {
      status: 200,
      body: { valid: true, agent_id: "axis:x:bot", operator_id: "x", status: "active", expires_at: "2099-01-01T00:00:00Z" },
    },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  const r = await c.verifyAIT("tok");
  assert.equal(r.valid, true);
  assert.equal(r.agent_id, "axis:x:bot");
});

test("verifyAIT throws AxisError on transport failure", async () => {
  const { fetchImpl } = makeFakeFetch([{ throws: new Error("ECONNRESET") }]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await assert.rejects(() => c.verifyAIT("tok"), (err) => err.code === ERR.REGISTRY_UNREACHABLE);
});

test("checkRevocation GETs /revocation/:slug", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ body: { revoked: false } }]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await c.checkRevocation("axis:x:bot");
  assert.equal(calls[0].url, "https://r/revocation/bot");
});

test("verifyDelegationChain GETs /delegations/:id/chain", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ body: { valid: true } }]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await c.verifyDelegationChain("deleg_123");
  assert.equal(calls[0].url, "https://r/delegations/deleg_123/chain");
});

// ── Auth requirement ──────────────────────────────────────────────────────

test("registerAgent without apiKey throws API_KEY_REQUIRED", async () => {
  const c = new AxisClient({ registryUrl: "https://r" });
  await assert.rejects(
    () => c.registerAgent({ operator: { email: "a@b" }, publicKey: "xyz" }),
    (err) => err.code === ERR.API_KEY_REQUIRED,
  );
});

test("registerAgent with apiKey sends Bearer header", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ status: 201, body: { did: "did:axis:prime:x" } }]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "key_abc", fetch: fetchImpl });
  await c.registerAgent({ operator: { email: "a@b.com" }, publicKey: "PUB" });
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, "https://r/register");
  assert.equal(calls[0].headers.Authorization, "Bearer key_abc");
  const body = JSON.parse(calls[0].body);
  assert.equal(body.operator.email, "a@b.com");
  assert.equal(body.publicKey, "PUB");
});

test("registerAgent validates operator.email or operator.domain present", async () => {
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k" });
  await assert.rejects(
    () => c.registerAgent({ operator: {}, publicKey: "x" }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("deactivateAgent DELETEs /agents/:slug with reason body", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: { ok: true } }]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await c.deactivateAgent("axis:x:bot", { reason: "rotation" });
  assert.equal(calls[0].method, "DELETE");
  assert.equal(calls[0].url, "https://r/agents/bot");
  assert.equal(JSON.parse(calls[0].body).reason, "rotation");
});

test("listAgents requires operator_id and auth", async () => {
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k" });
  await assert.rejects(() => c.listAgents({}), (err) => err.code === ERR.INVALID_INPUT);
  const noKey = new AxisClient({ registryUrl: "https://r" });
  await assert.rejects(
    () => noKey.listAgents({ operator_id: "x" }),
    (err) => err.code === ERR.API_KEY_REQUIRED,
  );
});

test("createDelegation validates required fields", async () => {
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k" });
  await assert.rejects(
    () => c.createDelegation({ issued_by: "a", issued_to: "b", scope: [], expires_at: "2099" }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
  await assert.rejects(
    () => c.createDelegation({ issued_by: "a", scope: ["read"], expires_at: "2099" }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("verifyDomain POSTs /operators/verify-domain with method default", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: {} }]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await c.verifyDomain({ email: "a@b.com", domain: "b.com" });
  const body = JSON.parse(calls[0].body);
  assert.equal(body.method, "dns_txt");
  assert.equal(body.domain, "b.com");
});

// ── Break-glass ───────────────────────────────────────────────────────────

test("forceDeactivateAgent requires non-empty reason", async () => {
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k" });
  await assert.rejects(
    () => c.forceDeactivateAgent("axis:x:bot", {}),
    (err) => err.code === ERR.INVALID_INPUT,
  );
  await assert.rejects(
    () => c.forceDeactivateAgent("axis:x:bot", { reason: "   " }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("forceRevokeDelegation POSTs with reason body", async () => {
  const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: { revoked: true } }]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await c.forceRevokeDelegation("deleg_1", { reason: "abuse report" });
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, "https://r/admin/force-revoke-delegation/deleg_1");
  assert.equal(JSON.parse(calls[0].body).reason, "abuse report");
});

// ── Error code mapping ────────────────────────────────────────────────────

test("401 response maps to UNAUTHORIZED", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 401, body: { error: { code: "unauthorized", message: "bad key" } } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await assert.rejects(
    () => c.registerAgent({ operator: { email: "a@b" }, publicKey: "p" }),
    (err) => err.code === ERR.UNAUTHORIZED && err.status === 401,
  );
});

test("403 not_your_resource maps to NOT_YOUR_RESOURCE", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 403, body: { error: { code: "not_your_resource", message: "nope" } } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await assert.rejects(
    () => c.deactivateAgent("axis:x:bot", { reason: "r" }),
    (err) => err.code === ERR.NOT_YOUR_RESOURCE,
  );
});

test("403 forbidden (role) maps to INSUFFICIENT_ROLE", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 403, body: { error: { code: "forbidden", message: "admin required" } } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await assert.rejects(
    () => c.adminStats(),
    (err) => err.code === ERR.INSUFFICIENT_ROLE,
  );
});

test("404 maps to NOT_FOUND", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 404, body: { error: { code: "not_found", message: "gone" } } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", fetch: fetchImpl });
  await assert.rejects(() => c.resolveAgent("ghost"), (err) => err.code === ERR.NOT_FOUND);
});

test("409 maps to CONFLICT", async () => {
  const { fetchImpl } = makeFakeFetch([
    { status: 409, body: { error: { code: "agent_already_exists", message: "collision" } } },
  ]);
  const c = new AxisClient({ registryUrl: "https://r", apiKey: "k", fetch: fetchImpl });
  await assert.rejects(
    () => c.registerAgent({ operator: { email: "a@b" }, publicKey: "p" }),
    (err) => err.code === ERR.CONFLICT,
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Security review 2026-05-08/09 — unshipped findings (S-L1..L3, S-M1..M3)
// Tests for the v0.2.3 hardening pass.
// ────────────────────────────────────────────────────────────────────────────

test("S-L2: constructor rejects http:// by default", () => {
  assert.throws(
    () => new AxisClient({ registryUrl: "http://registry.local" }),
    (err) => err instanceof AxisError && err.code === ERR.INVALID_INPUT && /https:\/\//.test(err.message),
  );
});

test("S-L2: constructor accepts http:// when allowInsecure: true is set", () => {
  const c = new AxisClient({ registryUrl: "http://registry.local", allowInsecure: true });
  assert.equal(c.registryUrl, "http://registry.local");
});

test("S-L2: constructor accepts https:// without allowInsecure", () => {
  const c = new AxisClient({ registryUrl: "https://registry.axisprime.ai" });
  assert.equal(c.registryUrl, "https://registry.axisprime.ai");
});

test("S-L2: constructor rejects non-http(s) schemes", () => {
  assert.throws(
    () => new AxisClient({ registryUrl: "file:///tmp/r" }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("S-L1: public calls do NOT send Authorization even when apiKey is set", async () => {
  let observedAuth = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedAuth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    return { ok: true, json: async () => ({ agent_id: "axis:op:a", status: "active" }) };
  };
  const c = new AxisClient({
    registryUrl: "https://r.example",
    apiKey: "secret-key-do-not-leak",
    fetch: fakeFetch,
  });
  await c.resolveAgent("axis:op:a");
  assert.equal(observedAuth, "MISSING", "public endpoint must not receive Authorization header");
});

test("S-L1: authenticated calls DO send Authorization when apiKey is set", async () => {
  let observedAuth = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedAuth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    return { ok: true, json: async () => ({ axis_id: "axis:op:new" }) };
  };
  const c = new AxisClient({
    registryUrl: "https://r.example",
    apiKey: "secret",
    fetch: fakeFetch,
  });
  await c.registerAgent({ operator: { email: "a@b" }, publicKey: "p" });
  assert.equal(observedAuth, "Bearer secret");
});

test("S-L3: _slugFromAgentId handles v0.1 axis:op:slug", () => {
  assert.equal(AxisClient._slugFromAgentId("axis:offworld:mira"), "mira");
});

test("S-L3: _slugFromAgentId handles v0.1 did:axis:registry:slug", () => {
  assert.equal(AxisClient._slugFromAgentId("did:axis:prime:mira"), "mira");
});

test("S-L3: _slugFromAgentId handles v0.2 did:axis:registry:operator:slug", () => {
  assert.equal(AxisClient._slugFromAgentId("did:axis:prime:offworld:mira"), "mira");
});

test("S-L3: _slugFromAgentId returns bare slug unchanged", () => {
  assert.equal(AxisClient._slugFromAgentId("just-a-slug"), "just-a-slug");
});

test("S-L3: _slugFromAgentId returns malformed input unchanged (no silent truncation)", () => {
  // Pre-fix behavior would .split(":").pop() and return "garbage" for any
  // colon-bearing string. New behavior: only matches known grammars.
  assert.equal(AxisClient._slugFromAgentId("not:a:valid:axis:thing:garbage"), "not:a:valid:axis:thing:garbage");
});

test("S-L3: _slugFromAgentId returns empty/null inputs unchanged", () => {
  assert.equal(AxisClient._slugFromAgentId(null), null);
  assert.equal(AxisClient._slugFromAgentId(""), "");
  assert.equal(AxisClient._slugFromAgentId(undefined), undefined);
});

test("S-M2: _abortable returns no-op when timeout is 0", () => {
  const c = new AxisClient({ registryUrl: "https://r.example", timeout: 0 });
  const { signal, clear } = c._abortable();
  assert.equal(signal, undefined);
  assert.doesNotThrow(() => clear());
});

test("S-M2: _abortable returns AbortController-backed signal when timeout is set", () => {
  const c = new AxisClient({ registryUrl: "https://r.example", timeout: 100 });
  const { signal, clear } = c._abortable();
  assert.ok(signal, "signal should be present");
  assert.equal(signal.aborted, false);
  clear();
});

test("S-M2: constructor rejects negative timeout", () => {
  assert.throws(
    () => new AxisClient({ registryUrl: "https://r.example", timeout: -1 }),
    (err) => err.code === ERR.INVALID_INPUT,
  );
});

test("S-M2: hung fetch aborts via timeout and surfaces as REGISTRY_UNREACHABLE", async () => {
  const hangingFetch = (_url, opts) =>
    new Promise((_, reject) => {
      if (opts && opts.signal) {
        opts.signal.addEventListener("abort", () => reject(new Error("aborted")));
      }
    });
  const c = new AxisClient({
    registryUrl: "https://r.example",
    timeout: 30,
    fetch: hangingFetch,
  });
  await assert.rejects(
    () => c.resolveAgent("axis:op:a"),
    (err) => err instanceof AxisError && err.code === ERR.REGISTRY_UNREACHABLE,
  );
});

test("S-M3: verifyAIT routes through _request and sends User-Agent when configured", async () => {
  let observedUA = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedUA = (opts && opts.headers && opts.headers["User-Agent"]) || "MISSING";
    return { ok: true, json: async () => ({ valid: true, agent_id: "axis:op:a", status: "active" }) };
  };
  const c = new AxisClient({
    registryUrl: "https://r.example",
    userAgent: "test-suite/1.0",
    fetch: fakeFetch,
  });
  const r = await c.verifyAIT("token");
  assert.equal(r.valid, true);
  assert.equal(observedUA, "test-suite/1.0");
});

test("S-M3: verifyAIT preserves {valid:false} semantic on 4xx token errors", async () => {
  const fakeFetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ error: { code: "ait_expired", message: "Token expired" } }),
  });
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  const r = await c.verifyAIT("expired-token");
  assert.equal(r.valid, false);
  assert.match(r.error, /expired/i);
});

test("S-M3: verifyAIT still throws on transport failure (REGISTRY_UNREACHABLE)", async () => {
  const failingFetch = async () => { throw new Error("ECONNREFUSED"); };
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: failingFetch });
  await assert.rejects(
    () => c.verifyAIT("token"),
    (err) => err instanceof AxisError && err.code === ERR.REGISTRY_UNREACHABLE,
  );
});

// ────────────────────────────────────────────────────────────────────────────
// v0.2.3 — WC-M2 presentingAIT + WC-L4 surfacing structured code on verifyAIT
// ────────────────────────────────────────────────────────────────────────────

test("WC-M2: resolveAgent without presentingAIT sends no Authorization header", async () => {
  let observedAuth = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedAuth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    return { ok: true, json: async () => ({ agent_id: "axis:op:a", status: "active" }) };
  };
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  await c.resolveAgent("axis:op:a");
  assert.equal(observedAuth, "MISSING");
});

test("WC-M2: resolveAgent with presentingAIT sends the AIT as Bearer", async () => {
  let observedAuth = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedAuth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    return {
      ok: true,
      json: async () => ({ agent_id: "axis:op:a", status: "active", display_name: "Mira" }),
    };
  };
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  const r = await c.resolveAgent("axis:op:a", { presentingAIT: "fake.ait.token" });
  assert.equal(observedAuth, "Bearer fake.ait.token");
  assert.equal(r.display_name, "Mira");
});

test("WC-M2: presentingAIT does NOT leak the registrar apiKey when client has one", async () => {
  let observedAuth = "MISSING";
  const fakeFetch = async (_url, opts) => {
    observedAuth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    return { ok: true, json: async () => ({}) };
  };
  // Client constructed with a registrar apiKey, then makes a presenting call.
  // The Bearer header must carry the AIT, NOT the apiKey.
  const c = new AxisClient({
    registryUrl: "https://r.example",
    apiKey: "secret-registrar-key",
    fetch: fakeFetch,
  });
  await c.resolveAgent("axis:op:a", { presentingAIT: "fake.ait.token" });
  assert.equal(observedAuth, "Bearer fake.ait.token");
  // Negative assertion: the registrar key must not appear
  assert.ok(!observedAuth.includes("secret-registrar-key"));
});

test("WC-M2: resolveDid + getOperator both accept presentingAIT", async () => {
  const seen = { resolve: "MISSING", op: "MISSING" };
  const fakeFetch = async (url, opts) => {
    const auth = (opts && opts.headers && opts.headers["Authorization"]) || "MISSING";
    if (url.includes("/resolve/")) seen.resolve = auth;
    else if (url.includes("/operators/")) seen.op = auth;
    return { ok: true, json: async () => ({}) };
  };
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  await c.resolveDid("did:axis:prime:op:a", { presentingAIT: "T1" });
  await c.getOperator("op-abc", { presentingAIT: "T2" });
  assert.equal(seen.resolve, "Bearer T1");
  assert.equal(seen.op, "Bearer T2");
});

test("WC-L4: verifyAIT surfaces code from valid:false response", async () => {
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({
      valid: false,
      code: "token_expired",
      agent_id: "axis:op:a",
      reason: "Token expired",
      expired_at: "2026-01-01T00:00:00Z",
    }),
  });
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  const r = await c.verifyAIT("expired.token");
  assert.equal(r.valid, false);
  assert.equal(r.code, "token_expired");
  assert.match(r.error, /expired/i);
  assert.equal(r.agent_id, "axis:op:a");
});

test("WC-L4: verifyAIT returns null code on older registries that omit it", async () => {
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({ valid: false, reason: "Invalid signature" }),
  });
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: fakeFetch });
  const r = await c.verifyAIT("bad.sig");
  assert.equal(r.valid, false);
  assert.equal(r.code, null);
  assert.match(r.error, /signature/i);
});

test("WC-L4: verifyAIT no-token call returns code 'missing_token'", async () => {
  const c = new AxisClient({ registryUrl: "https://r.example", fetch: async () => ({}) });
  const r = await c.verifyAIT("");
  assert.equal(r.valid, false);
  assert.equal(r.code, "missing_token");
});
