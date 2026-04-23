/**
 * Example: verify an AIT arriving on an incoming HTTP request.
 *
 * Drop this inside any Node / Cloudflare Worker / Deno HTTP handler.
 * It extracts a Bearer token from the Authorization header and asks
 * the registry whether the token is valid. Gate your business logic
 * on the verified result.
 *
 * Environment variables:
 *   AXIS_REGISTRY_URL  — defaults to https://registry.axisprime.ai
 *   PORT               — defaults to 8787
 *
 * Run:
 *   node examples/verify-incoming.js
 *   curl -H "Authorization: Bearer <AIT>" http://localhost:8787/whoami
 */

import { createServer } from "node:http";
import { AxisClient } from "../src/index.js";

const registryUrl = process.env.AXIS_REGISTRY_URL || "https://registry.axisprime.ai";
const port = Number(process.env.PORT || 8787);

const client = new AxisClient({ registryUrl });

const server = createServer(async (req, res) => {
  const auth = req.headers["authorization"] || "";
  const match = /^Bearer (.+)$/.exec(auth);
  if (!match) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Missing Bearer token" }));
    return;
  }

  const result = await client.verifyAIT(match[1]);
  if (!result.valid) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: result.error }));
    return;
  }

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    authenticated_as: result.agent_id,
    operator: result.operator_id,
    status: result.status,
    token_expires_at: result.expires_at,
  }));
});

server.listen(port, () => {
  console.log(`Verifier listening on :${port}  (registry: ${registryUrl})`);
});
