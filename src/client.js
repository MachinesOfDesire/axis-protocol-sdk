/**
 * AxisClient — the canonical client for the AXIS reference registry.
 *
 * Three roles of caller, one client class:
 *
 *   PUBLIC (no apiKey needed):
 *     resolveAgent, resolveDid, getOperator, verifyAIT, verifyDid,
 *     verifySignature, checkRevocation, getDelegation,
 *     verifyDelegationChain, getAccessPolicy
 *
 *   REGISTRAR (apiKey required):
 *     registerAgent, deactivateAgent, listAgents,
 *     createDelegation, revokeDelegation,
 *     verifyDomain, checkDomain,
 *     createAgent (convenience: keypair + registerAgent + sign helper)
 *
 *   ADMIN / SUPER_ADMIN (apiKey with elevated role, server enforces):
 *     adminListOperators, adminGetAgent, adminListAgents,
 *     adminAudit, adminStats,
 *     forceDeactivateAgent, forceRevokeDelegation
 *
 * If the server rejects a call for role reasons it throws AxisError with
 * status 401 or 403 and a code the caller can branch on. The SDK does not
 * try to predict locally what role the apiKey has — the server is the
 * source of truth.
 *
 * Construction:
 *   const client = new AxisClient({
 *     registryUrl: "https://registry.axisprime.ai",
 *     apiKey: process.env.AXIS_REGISTRAR_KEY,  // optional
 *     fetch: customFetch,                       // optional override
 *   });
 */

import { AxisError, ERR } from "./errors.js";
import { generateKeypair, signAIT, canonicalize, signCanonical } from "./crypto.js";

export class AxisClient {
  constructor({ registryUrl, apiKey = null, fetch: fetchImpl = null, userAgent = null } = {}) {
    if (!registryUrl) {
      throw new AxisError(ERR.INVALID_INPUT, "AxisClient: registryUrl is required");
    }
    this.registryUrl = registryUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.userAgent = userAgent;
    this._fetch = fetchImpl || ((...args) => fetch(...args));
  }

  // ── Internal HTTP helpers ────────────────────────────────────────────────

  async _request(path, { method = "GET", body, requireAuth = false, headers = {} } = {}) {
    const url = `${this.registryUrl}${path}`;
    const reqHeaders = { ...headers };
    if (body !== undefined) reqHeaders["Content-Type"] = "application/json";
    if (this.userAgent) reqHeaders["User-Agent"] = this.userAgent;
    if (requireAuth || this.apiKey) {
      if (!this.apiKey) {
        throw new AxisError(ERR.API_KEY_REQUIRED, `Registrar API key required for ${method} ${path}`);
      }
      reqHeaders["Authorization"] = `Bearer ${this.apiKey}`;
    }

    let res;
    try {
      res = await this._fetch(url, {
        method,
        headers: reqHeaders,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new AxisError(
        ERR.REGISTRY_UNREACHABLE,
        `Registry unreachable at ${url}: ${e.message}`,
        { cause: e }
      );
    }

    let data = null;
    try {
      data = await res.json();
    } catch {}

    if (!res.ok) {
      const serverCode = data && data.error && (data.error.code || data.error);
      const serverMsg = data && data.error && (data.error.message || data.error);
      throw new AxisError(
        this._mapServerCode(res.status, serverCode),
        serverMsg || `Registry returned HTTP ${res.status}`,
        { status: res.status, body: data, serverCode }
      );
    }
    return data;
  }

  _mapServerCode(status, code) {
    if (status === 401) return ERR.UNAUTHORIZED;
    if (status === 403 && code === "not_your_resource") return ERR.NOT_YOUR_RESOURCE;
    if (status === 403 && code === "forbidden") return ERR.INSUFFICIENT_ROLE;
    if (status === 403) return ERR.FORBIDDEN;
    if (status === 404) return ERR.NOT_FOUND;
    if (status === 409) return ERR.CONFLICT;
    return ERR.REGISTRY_HTTP;
  }

  /** Normalize an AXIS identifier (accepts axis:op:slug, did:axis:prime:slug, or bare slug). */
  static _slugFromAgentId(id) {
    if (!id) return id;
    if (id.startsWith("did:")) return id.split(":").pop();
    if (id.includes(":")) return id.split(":").pop();
    return id;
  }

  // ═════════════════════════════════════════════════════════════════════════
  // PUBLIC ENDPOINTS (no auth)
  // ═════════════════════════════════════════════════════════════════════════

  /** GET /.well-known/axis-access — platform access policy advertisement. */
  async getAccessPolicy() {
    return this._request("/.well-known/axis-access");
  }

  /** GET /agents/:id — resolve an agent identity record by axis_id, did, or slug. */
  async resolveAgent(agentIdOrSlug) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    return this._request(`/agents/${encodeURIComponent(slug)}`);
  }

  /** GET /resolve/:did — resolve a DID to a DID Document. */
  async resolveDid(did) {
    if (!did) throw new AxisError(ERR.INVALID_INPUT, "did is required");
    return this._request(`/resolve/${encodeURIComponent(did)}`);
  }

  /** GET /operators/:id — get an operator record. */
  async getOperator(operatorId) {
    if (!operatorId) throw new AxisError(ERR.INVALID_INPUT, "operatorId is required");
    return this._request(`/operators/${encodeURIComponent(operatorId)}`);
  }

  /**
   * Verify an AXIS Identity Token via the registry.
   * Returns { valid, agent_id, operator_id, status, expires_at } on success.
   * Returns { valid: false, error } on failure — does NOT throw on a bad token.
   * Only throws on transport / registry errors.
   */
  async verifyAIT(token) {
    if (!token) return { valid: false, error: "No token provided" };
    const url = `${this.registryUrl}/verify?token=${encodeURIComponent(token)}`;
    let res;
    try {
      res = await this._fetch(url);
    } catch (e) {
      throw new AxisError(ERR.REGISTRY_UNREACHABLE, `Registry unreachable: ${e.message}`, { cause: e });
    }
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok || !data || data.valid !== true) {
      return { valid: false, error: (data && (data.error?.message || data.error)) || `HTTP ${res.status}` };
    }
    return {
      valid: true,
      agent_id: data.agent_id,
      operator_id: data.operator_id,
      status: data.status,
      expires_at: data.expires_at,
    };
  }

  /** GET /verify/:did — verify a DID (agent) identity without a token. */
  async verifyDid(did) {
    if (!did) throw new AxisError(ERR.INVALID_INPUT, "did is required");
    return this._request(`/verify/${encodeURIComponent(did)}`);
  }

  /** POST /verify/signature — verify a signature against a stored agent key. */
  async verifySignature({ agent_id, message, signature, public_key } = {}) {
    if (!message || !signature) {
      throw new AxisError(ERR.INVALID_INPUT, "message and signature are required");
    }
    const body = { message, signature };
    if (agent_id) body.agent_id = agent_id;
    if (public_key) body.public_key = public_key;
    return this._request("/verify/signature", { method: "POST", body });
  }

  /** GET /revocation/:agent_id — check whether an agent is revoked/deactivated. */
  async checkRevocation(agentIdOrSlug) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    return this._request(`/revocation/${encodeURIComponent(slug)}`);
  }

  /** GET /delegations/:id — fetch a delegation record. */
  async getDelegation(delegationId) {
    if (!delegationId) throw new AxisError(ERR.INVALID_INPUT, "delegationId is required");
    return this._request(`/delegations/${encodeURIComponent(delegationId)}`);
  }

  /** GET /delegations/:id/chain — walk the delegation chain for verification. */
  async verifyDelegationChain(delegationId) {
    if (!delegationId) throw new AxisError(ERR.INVALID_INPUT, "delegationId is required");
    return this._request(`/delegations/${encodeURIComponent(delegationId)}/chain`);
  }

  // ═════════════════════════════════════════════════════════════════════════
  // REGISTRAR-AUTHENTICATED ENDPOINTS (apiKey required)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * POST /register — register a new agent under an operator you own.
   *
   * @param {object} opts
   * @param {{email?: string, domain?: string}} opts.operator  Operator identity (one required)
   * @param {string} opts.publicKey                             Ed25519 public key, base64url
   * @param {{name?: string, description?: string}} [opts.metadata]
   * @param {object} [opts.service]                             Optional service endpoint spec
   * @param {{proofValue: string}} [opts.proof]                 Optional Ed25519 proof of key ownership
   */
  async registerAgent({ operator, publicKey, metadata, service, proof } = {}) {
    if (!operator || (!operator.email && !operator.domain)) {
      throw new AxisError(ERR.INVALID_INPUT, "operator.email or operator.domain is required");
    }
    if (!publicKey) throw new AxisError(ERR.INVALID_INPUT, "publicKey is required");
    const body = { operator, publicKey };
    if (metadata) body.metadata = metadata;
    if (service) body.service = service;
    if (proof) body.proof = proof;
    return this._request("/register", { method: "POST", body, requireAuth: true });
  }

  /**
   * DELETE /agents/:id — deactivate an agent you (or your registrar) own.
   * For cross-tenant force-deactivation use forceDeactivateAgent (super_admin only).
   */
  async deactivateAgent(agentIdOrSlug, { reason } = {}) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    return this._request(`/agents/${encodeURIComponent(slug)}`, {
      method: "DELETE",
      body: reason ? { reason } : undefined,
      requireAuth: true,
    });
  }

  /**
   * GET /agents?operator_id=... — list agents under an operator you own.
   * Returns { agents: [...] }.
   */
  async listAgents({ operator_id } = {}) {
    if (!operator_id) throw new AxisError(ERR.INVALID_INPUT, "operator_id is required");
    return this._request(`/agents?operator_id=${encodeURIComponent(operator_id)}`, {
      requireAuth: true,
    });
  }

  /**
   * POST /delegations — create a delegation credential.
   *
   * @param {object} opts
   * @param {string} opts.issued_by                    Full axis id of the issuer (agent or operator)
   * @param {string} opts.issued_to                    Full axis id of the recipient
   * @param {string[]} opts.scope                      Non-empty array of scope tokens
   * @param {string} opts.expires_at                   ISO-8601 timestamp
   * @param {object} [opts.constraints]                Optional constraints object
   * @param {string} [opts.parent_credential_id]       Optional parent delegation for attenuation
   * @param {string} [opts.signature]                  Optional signature over canonical body
   */
  async createDelegation({ issued_by, issued_to, scope, expires_at, constraints, parent_credential_id, signature } = {}) {
    if (!issued_by) throw new AxisError(ERR.INVALID_INPUT, "issued_by is required");
    if (!issued_to) throw new AxisError(ERR.INVALID_INPUT, "issued_to is required");
    if (!Array.isArray(scope) || scope.length === 0) {
      throw new AxisError(ERR.INVALID_INPUT, "scope must be a non-empty array");
    }
    if (!expires_at) throw new AxisError(ERR.INVALID_INPUT, "expires_at is required");
    const body = { issued_by, issued_to, scope, expires_at };
    if (constraints) body.constraints = constraints;
    if (parent_credential_id) body.parent_credential_id = parent_credential_id;
    if (signature) body.signature = signature;
    return this._request("/delegations", { method: "POST", body, requireAuth: true });
  }

  /** DELETE /delegations/:id — revoke a delegation you own. */
  async revokeDelegation(delegationId, { reason } = {}) {
    if (!delegationId) throw new AxisError(ERR.INVALID_INPUT, "delegationId is required");
    return this._request(`/delegations/${encodeURIComponent(delegationId)}`, {
      method: "DELETE",
      body: reason ? { reason } : undefined,
      requireAuth: true,
    });
  }

  // ── Operator domain verification ────────────────────────────────────────

  /**
   * POST /operators/verify-domain — initiate (or re-initiate) a domain claim
   * for the caller's operator. Returns the verification token and instructions.
   *
   * @param {{email: string, domain?: string, method?: "dns_txt"|"http_file"}} opts
   */
  async verifyDomain({ email, domain, method = "dns_txt" } = {}) {
    if (!email) throw new AxisError(ERR.INVALID_INPUT, "email is required");
    return this._request("/operators/verify-domain", {
      method: "POST",
      body: { email, domain, method },
      requireAuth: true,
    });
  }

  /**
   * POST /operators/verify-domain/check — confirm ownership after the DNS/HTTP
   * record is in place. On success the operator is upgraded to the domain tier.
   */
  async checkDomain({ domain, token } = {}) {
    if (!domain) throw new AxisError(ERR.INVALID_INPUT, "domain is required");
    if (!token) throw new AxisError(ERR.INVALID_INPUT, "token is required");
    return this._request("/operators/verify-domain/check", {
      method: "POST",
      body: { domain, token },
      requireAuth: true,
    });
  }

  // ═════════════════════════════════════════════════════════════════════════
  // ADMIN / SUPER_ADMIN ENDPOINTS (role enforced server-side)
  // ═════════════════════════════════════════════════════════════════════════

  /** GET /admin/operators — list all operators across tenants. Admin+. */
  async adminListOperators({ limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return this._request(`/admin/operators?${params}`, { requireAuth: true });
  }

  /** GET /admin/agents/:id — cross-tenant agent lookup. Admin+. */
  async adminGetAgent(agentIdOrSlug) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    return this._request(`/admin/agents/${encodeURIComponent(slug)}`, { requireAuth: true });
  }

  /** GET /admin/agents — list agents across all tenants. Admin+. */
  async adminListAgents({ limit = 50, offset = 0, status } = {}) {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (status) params.set("status", status);
    return this._request(`/admin/agents?${params}`, { requireAuth: true });
  }

  /** GET /admin/audit — cross-tenant audit log. Admin+. */
  async adminAudit({ limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return this._request(`/admin/audit?${params}`, { requireAuth: true });
  }

  /** GET /admin/stats — registry-wide stats. Admin+. */
  async adminStats() {
    return this._request("/admin/stats", { requireAuth: true });
  }

  /**
   * POST /admin/force-deactivate-agent/:id — break-glass deactivation.
   * Super_admin only. Server writes an audit row with {reason, role} BEFORE
   * the mutation and aborts if the audit write fails. Reason is required.
   */
  async forceDeactivateAgent(agentIdOrSlug, { reason } = {}) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    if (!reason || !reason.trim()) {
      throw new AxisError(ERR.INVALID_INPUT, "reason is required for break-glass calls");
    }
    return this._request(`/admin/force-deactivate-agent/${encodeURIComponent(slug)}`, {
      method: "POST",
      body: { reason },
      requireAuth: true,
    });
  }

  /**
   * POST /admin/force-revoke-delegation/:id — break-glass delegation revocation.
   * Super_admin only. Same audit-first semantics as forceDeactivateAgent.
   */
  async forceRevokeDelegation(delegationId, { reason } = {}) {
    if (!delegationId) throw new AxisError(ERR.INVALID_INPUT, "delegationId is required");
    if (!reason || !reason.trim()) {
      throw new AxisError(ERR.INVALID_INPUT, "reason is required for break-glass calls");
    }
    return this._request(`/admin/force-revoke-delegation/${encodeURIComponent(delegationId)}`, {
      method: "POST",
      body: { reason },
      requireAuth: true,
    });
  }

  // ═════════════════════════════════════════════════════════════════════════
  // HIGH-LEVEL CONVENIENCE
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Generate a fresh Ed25519 keypair, register the agent with proof of key
   * ownership, and return a session with a sign() helper.
   *
   * Useful for tests, demos, and short-lived agents that don't need to
   * persist their key material. For production agents, generate + persist
   * the keypair yourself and call registerAgent() directly.
   *
   * @returns {Promise<AgentSession>}
   */
  async createAgent({ operator, metadata, service } = {}) {
    if (!operator || (!operator.email && !operator.domain)) {
      throw new AxisError(ERR.INVALID_INPUT, "operator.email or operator.domain is required");
    }
    const keypair = await generateKeypair();
    // Build proof: sign the canonical body minus the proof field.
    const proofBody = { operator, publicKey: keypair.publicKeyB64 };
    if (metadata) proofBody.metadata = metadata;
    if (service) proofBody.service = service;
    const proofValue = await signCanonical(keypair.privateKey, proofBody);
    const record = await this.registerAgent({
      operator,
      publicKey: keypair.publicKeyB64,
      metadata,
      service,
      proof: { proofValue },
    });
    const agent_id = record.axis_id || record.did;
    const sign = ({ ttl = 300, claims = {} } = {}) =>
      signAIT({ privateKey: keypair.privateKey, agentId: agent_id, ttl, claims });
    return {
      agent_id,
      did: record.did,
      axis_id: record.axis_id,
      record,
      keypair,
      sign,
    };
  }
}
