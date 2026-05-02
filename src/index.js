/**
 * AXIS Protocol SDK — public entry point.
 *
 * Usage:
 *
 *   import { AxisClient, generateKeypair, signAIT } from "axis-protocol-sdk";
 *
 *   // 1. Verify a token (public, no auth)
 *   const client = new AxisClient({ registryUrl: "https://registry.axisprime.ai" });
 *   const result = await client.verifyAIT(someToken);
 *   if (!result.valid) throw new Error(result.error);
 *
 *   // 2. Register an agent (registrar API key required)
 *   const reg = new AxisClient({
 *     registryUrl: "https://registry.axisprime.ai",
 *     apiKey: process.env.AXIS_REGISTRAR_KEY,
 *   });
 *   const session = await reg.createAgent({
 *     operator: { email: "ops@example.com" },
 *     metadata: { name: "Mira" },
 *   });
 *   const ait = await session.sign({ ttl: 300, claims: { act: "publish" } });
 */

export { AxisClient } from "./client.js";
export {
  generateKeypair,
  signAIT,
  decodeAIT,
  verifyAITLocally,
  importPrivateKey,
  importPublicKey,
  canonicalize,
  signCanonical,
} from "./crypto.js";
export { b64urlEncode, b64urlDecode, b64urlDecodeString } from "./base64url.js";
export { AxisError, ERR } from "./errors.js";

export const SDK_VERSION = "0.2.1";
export const AXIS_PROTOCOL_VERSION = "0.1";
