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

// SDK_VERSION is derived from package.json so the two cannot drift. JSON
// import attributes are supported on the SDK's targets: Node 20+ (the
// engines pin), Cloudflare Workers (wrangler/esbuild inlines the JSON at
// bundle time), and modern browsers / bundlers.
import pkg from "../package.json" with { type: "json" };

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
  signDelegation,
} from "./crypto.js";
export { jcsCanonicalize, jcsCanonicalizeBytes } from "./jcs.js";
export { b64urlEncode, b64urlDecode, b64urlDecodeString } from "./base64url.js";
export { AxisError, ERR } from "./errors.js";

export const SDK_VERSION = pkg.version;
// JCS canonicalization, the DC signer, and the proofType'd registration proof
// are AXIS Protocol v0.2 §6.1 features (SDK v0.3). The client still
// interoperates with v0.1 registries (the registry accepts both proof regimes).
export const AXIS_PROTOCOL_VERSION = "0.2";
