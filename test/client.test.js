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
