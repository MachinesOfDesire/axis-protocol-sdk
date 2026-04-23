/**
 * AXIS SDK error class. Carries a stable `code` so callers can branch on
 * specific error types without parsing English.
 */

export class AxisError extends Error {
  constructor(code, message, { cause, status, body, serverCode } = {}) {
    super(message);
    this.name = "AxisError";
    this.code = code;
    if (cause) this.cause = cause;
    if (status !== undefined) this.status = status;
    if (body !== undefined) this.body = body;
    if (serverCode !== undefined) this.serverCode = serverCode;
  }
}

export const ERR = {
  // Transport / generic
  REGISTRY_UNREACHABLE: "REGISTRY_UNREACHABLE",
  REGISTRY_HTTP: "REGISTRY_HTTP",
  REGISTRY_BAD_RESPONSE: "REGISTRY_BAD_RESPONSE",

  // Auth
  API_KEY_REQUIRED: "API_KEY_REQUIRED",
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  INSUFFICIENT_ROLE: "INSUFFICIENT_ROLE",
  NOT_YOUR_RESOURCE: "NOT_YOUR_RESOURCE",

  // Input / state
  INVALID_INPUT: "INVALID_INPUT",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",

  // AIT / token
  AIT_INVALID: "AIT_INVALID",
  AIT_EXPIRED: "AIT_EXPIRED",

  // Agent state
  AGENT_NOT_FOUND: "AGENT_NOT_FOUND",
  AGENT_REVOKED: "AGENT_REVOKED",
};
