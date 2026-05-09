/**
 * Example: create a scoped delegation, resolve it, then revoke it.
 *
 * A delegation is how one agent grants another agent (or operator) a
 * scoped, time-bounded permission. This is the "hire a specialist for
 * two weeks" pattern in miniature.
 *
 * Environment variables:
 *   AXIS_REGISTRY_URL    — defaults to https://registry.axisprime.ai
 *   AXIS_REGISTRAR_KEY   — your registrar API key (required)
 *   AXIS_OPERATOR_EMAIL  — operator to register agents under (required)
 *
 * Run:
 *   AXIS_REGISTRAR_KEY=... AXIS_OPERATOR_EMAIL=ops@example.com \
 *     node examples/delegation.js
 */

import { AxisClient, AxisError } from "../src/index.js";

const registryUrl = process.env.AXIS_REGISTRY_URL || "https://registry.axisprime.ai";
const apiKey = process.env.AXIS_REGISTRAR_KEY;
const email = process.env.AXIS_OPERATOR_EMAIL;

if (!apiKey) throw new Error("AXIS_REGISTRAR_KEY is required");
if (!email) throw new Error("AXIS_OPERATOR_EMAIL is required");

const client = new AxisClient({ registryUrl, apiKey });

try {
  // Step 1: register an issuer and a recipient agent, both under the same operator.
  const issuer = await client.createAgent({
    operator: { email },
    metadata: { name: `issuer-${Date.now()}` },
  });
  const recipient = await client.createAgent({
    operator: { email },
    metadata: { name: `recipient-${Date.now()}` },
  });
  console.log("Issuer:   ", issuer.axis_id);
  console.log("Recipient:", recipient.axis_id);

  // Step 2: create a 14-day scoped delegation, non-sub-delegable.
  // Note: the canonical timestamp field is `expires` (per AXIS spec v0.1 §4.4),
  // not the historical `expires_at` alias.
  const delegation = await client.createDelegation({
    issued_by: issuer.axis_id,
    issued_to: recipient.axis_id,
    scope: ["research:read", "draft:write"],
    expires: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(),
    constraints: { max_articles: 1, can_subdelegate: false },
  });
  console.log("\nCreated delegation:", delegation.id || delegation.delegation_id);

  // Step 3: resolve it back from the registry to confirm it landed.
  const delegationId = delegation.id || delegation.delegation_id;
  const fetched = await client.getDelegation(delegationId);
  console.log("Resolved:", fetched);

  // Step 4: revoke it and confirm.
  await client.revokeDelegation(delegationId, { reason: "demo cleanup" });
  console.log("Revoked ", delegationId);
} catch (err) {
  if (err instanceof AxisError) {
    console.error(`AxisError [${err.code}]${err.status ? ` (HTTP ${err.status})` : ""}: ${err.message}`);
    if (err.body) console.error("Server body:", JSON.stringify(err.body, null, 2));
    process.exit(1);
  }
  throw err;
}
