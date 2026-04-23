/**
 * Example: register a fresh agent and sign a token.
 *
 * Environment variables:
 *   AXIS_REGISTRY_URL      — defaults to https://registry.axisprime.ai
 *   AXIS_REGISTRAR_KEY     — your registrar API key (required)
 *   AXIS_OPERATOR_EMAIL    — the operator account to register under (required)
 *
 * Run:
 *   AXIS_REGISTRAR_KEY=... AXIS_OPERATOR_EMAIL=ops@example.com \
 *     node examples/register-and-sign.js
 */

import { AxisClient, AxisError } from "../src/index.js";

const registryUrl = process.env.AXIS_REGISTRY_URL || "https://registry.axisprime.ai";
const apiKey = process.env.AXIS_REGISTRAR_KEY;
const email = process.env.AXIS_OPERATOR_EMAIL;

if (!apiKey) throw new Error("AXIS_REGISTRAR_KEY is required");
if (!email) throw new Error("AXIS_OPERATOR_EMAIL is required");

const client = new AxisClient({ registryUrl, apiKey });

try {
  const session = await client.createAgent({
    operator: { email },
    metadata: {
      name: `example-${Date.now()}`,
      description: "Created by register-and-sign.js example",
    },
  });

  console.log("Registered agent:");
  console.log("  axis_id:", session.axis_id);
  console.log("  did:    ", session.did);

  const ait = await session.sign({ ttl: 60, claims: { purpose: "demo" } });
  console.log("\nSigned AIT (first 80 chars):", ait.slice(0, 80), "...");

  // Round-trip: ask the registry to verify the token we just signed.
  const result = await client.verifyAIT(ait);
  console.log("\nVerification result:", result);
} catch (err) {
  if (err instanceof AxisError) {
    console.error(`AxisError [${err.code}]${err.status ? ` (HTTP ${err.status})` : ""}: ${err.message}`);
    if (err.body) console.error("Server body:", JSON.stringify(err.body, null, 2));
    process.exit(1);
  }
  throw err;
}
