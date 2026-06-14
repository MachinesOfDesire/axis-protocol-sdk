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
  /**
   * @param {object} opts
   * @param {string} opts.registryUrl              Required. MUST be https:// unless allowInsecure is set.
   * @param {string} [opts.apiKey]                 Registrar API key. Only sent on requireAuth=true paths (closes S-L1).
   * @param {Function} [opts.fetch]                Optional fetch override (testing).
   * @param {string} [opts.userAgent]              Optional User-Agent header value.
   * @param {number} [opts.timeout=30000]          Per-request timeout in ms. AbortController-based. Pass 0 to disable. (Closes S-M2.)
   * @param {boolean} [opts.allowInsecure=false]   Permit http:// registryUrl. Required for local dev against a non-TLS registry. (Closes S-L2.)
   */
  constructor({
    registryUrl,
    apiKey = null,
    fetch: fetchImpl = null,
    userAgent = null,
    timeout = 30000,
    allowInsecure = false,
  } = {}) {
    if (!registryUrl) {
      throw new AxisError(ERR.INVALID_INPUT, "AxisClient: registryUrl is required");
    }
    if (!/^https?:\/\//i.test(registryUrl)) {
      throw new AxisError(ERR.INVALID_INPUT, "AxisClient: registryUrl must start with https:// or http://");
    }
    if (!allowInsecure && /^http:\/\//i.test(registryUrl)) {
      throw new AxisError(
        ERR.INVALID_INPUT,
        "AxisClient: registryUrl must use https:// (pass allowInsecure: true for local dev against a plaintext registry)"
      );
    }
    if (typeof timeout !== "number" || timeout < 0) {
      throw new AxisError(ERR.INVALID_INPUT, "AxisClient: timeout must be a non-negative number (ms); pass 0 to disable");
    }
    this.registryUrl = registryUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.userAgent = userAgent;
    this.timeout = timeout;
    this._fetch = fetchImpl || ((...args) => fetch(...args));
  }

  // ── Internal HTTP helpers ────────────────────────────────────────────────

  /**
   * Build a fetch options object with an AbortController-based timeout. Returns
   * { signal, clear } — caller MUST invoke clear() once the response resolves
   * (or rejects) to prevent the timer from leaking.
   */
  _abortable() {
    if (!this.timeout || typeof AbortController === "undefined") {
      return { signal: undefined, clear: () => {} };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("timeout")), this.timeout);
    return { signal: controller.signal, clear: () => clearTimeout(timer) };
  }

  async _request(path, { method = "GET", body, requireAuth = false, headers = {}, presentingAIT = null } = {}) {
    const url = `${this.registryUrl}${path}`;
    const reqHeaders = { ...headers };
    if (body !== undefined) reqHeaders["Content-Type"] = "application/json";
    if (this.userAgent) reqHeaders["User-Agent"] = this.userAgent;
    // S-L1: only attach Authorization when the endpoint explicitly requires
    // auth. Previously, having apiKey set caused the header to be sent on
    // EVERY call, including public endpoints, leaking the key to the
    // registry's public read paths (and to any intermediary that logs
    // headers). Public endpoints discard the header server-side but the
    // SDK should not be sending it in the first place.
    //
    // WC-M2 (v0.2.3): a caller may pass `presentingAIT` to send a per-call
    // Bearer header carrying an AIT (rather than the constructor-time apiKey).
    // Used by consumers like axis-comments-ghost to unlock the presentation
    // layer on public-endpoint reads — per AXIS Protocol v0.1.1 §5.2,
    // presenting a valid AIT in the Authorization header unlocks display
    // name, verification tier, and other presentation-layer fields. The
    // presenting AIT takes precedence over the registrar apiKey if both
    // happen to apply; the typical use is a public client (no apiKey) that
    // wants the presentation-layer unlock for a single resolve call.
    if (presentingAIT) {
      reqHeaders["Authorization"] = `Bearer ${presentingAIT}`;
    } else if (requireAuth) {
      if (!this.apiKey) {
        throw new AxisError(ERR.API_KEY_REQUIRED, `Registrar API key required for ${method} ${path}`);
      }
      reqHeaders["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const { signal, clear } = this._abortable();
    let res;
    try {
      res = await this._fetch(url, {
        method,
        headers: reqHeaders,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal,
      });
    } catch (e) {
      clear();
      // AbortError from our own timeout surfaces as REGISTRY_UNREACHABLE
      // with a clear message; downstream errors stay wrapped the same way.
      throw new AxisError(
        ERR.REGISTRY_UNREACHABLE,
        `Registry unreachable at ${url}: ${e.message}`,
        { cause: e }
      );
    }
    clear();

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

  /**
   * Normalize an AXIS identifier to the slug used in URL paths.
   * Accepts:
   *   - `axis:{operator}:{slug}`                       (canonical agent ID, spec §4.1)
   *   - `did:axis:{registry}:{slug}`                   (v0.1 DID form)
   *   - `did:axis:{registry}:{operator}:{slug}`        (v0.2 DID form, operator-namespaced)
   *   - bare `{slug}`                                  (already-normalized)
   *
   * S-L3: uses an explicit grammar instead of `.split(":").pop()`. The old
   * approach silently truncated slugs containing characters that look like
   * separators (none allowed by spec, but defensive against malformed input
   * from non-spec-compliant registries).
   */
  static _slugFromAgentId(id) {
    if (!id) return id;
    // did:axis:{registry}:{operator}:{slug} (v0.2) — five segments
    const didV2 = /^did:axis:[^:]+:[^:]+:([^:]+)$/.exec(id);
    if (didV2) return didV2[1];
    // did:axis:{registry}:{slug} (v0.1) — four segments
    const didV1 = /^did:axis:[^:]+:([^:]+)$/.exec(id);
    if (didV1) return didV1[1];
    // axis:{operator}:{slug} — three segments
    const axisId = /^axis:[^:]+:([^:]+)$/.exec(id);
    if (axisId) return axisId[1];
    // Bare slug or unknown shape — return unchanged
    return id;
  }

  // ═════════════════════════════════════════════════════════════════════════
  // PUBLIC ENDPOINTS (no auth)
  // ═════════════════════════════════════════════════════════════════════════

  /** GET /.well-known/axis-access — platform access policy advertisement. */
  async getAccessPolicy() {
    return this._request("/.well-known/axis-access");
  }

  /**
   * GET /agents/:id — resolve an agent identity record by axis_id, did, or slug.
   *
   * @param {string} agentIdOrSlug
   * @param {object} [opts]
   * @param {string} [opts.presentingAIT]  When supplied, sent as Bearer to unlock
   *   the registry's presentation layer (display_name, verification_tier, etc.)
   *   per AXIS Protocol v0.1.1 §5.2. Use this when a verifier wants the
   *   presentation-layer fields after verifying an AIT from a caller.
   *   Without it, only the public layer is returned. Added in SDK v0.2.3.
   */
  async resolveAgent(agentIdOrSlug, { presentingAIT } = {}) {
    const slug = AxisClient._slugFromAgentId(agentIdOrSlug);
    return this._request(`/agents/${encodeURIComponent(slug)}`, { presentingAIT });
  }

  /**
   * GET /resolve/:did — resolve a DID to a DID Document.
   *
   * @param {string} did
   * @param {object} [opts]
   * @param {string} [opts.presentingAIT]  See resolveAgent. Added in SDK v0.2.3.
   */
  async resolveDid(did, { presentingAIT } = {}) {
    if (!did) throw new AxisError(ERR.INVALID_INPUT, "did is required");
    return this._request(`/resolve/${encodeURIComponent(did)}`, { presentingAIT });
  }

  /**
   * GET /operators/:id — get an operator record.
   *
   * @param {string} operatorId
   * @param {object} [opts]
   * @param {string} [opts.presentingAIT]  See resolveAgent. Added in SDK v0.2.3.
   */
  async getOperator(operatorId, { presentingAIT } = {}) {
    if (!operatorId) throw new AxisError(ERR.INVALID_INPUT, "operatorId is required");
    return this._request(`/operators/${encodeURIComponent(operatorId)}`, { presentingAIT });
  }

  /**
   * Verify an AXIS Identity Token via the registry.
   * Returns { valid, agent_id, operator_id, status, expires_at } on success.
   * Returns { valid: false, error } on failure — does NOT throw on a bad token.
   * Only throws on transport / registry errors (network failure, registry
   * down, timeout).
   *
   * S-M3: routes through _request() so this call benefits from the same
   * User-Agent header, AbortController timeout, and error-code surface as
   * every other call. The {valid:false} semantic is preserved by catching
   * AxisError sourced from non-2xx responses; transport errors still throw.
   */
  async verifyAIT(token) {
    if (!token) return { valid: false, code: "missing_token", error: "No token provided" };
    try {
      const data = await this._request(`/verify?token=${encodeURIComponent(token)}`);
      if (!data || data.valid !== true) {
        // v0.2.3: registry now emits a stable `code` field on valid:false
        // responses (invalid_signature, token_expired, agent_revoked,
        // agent_suspended). Surface it directly so callers can branch on
        // a stable machine-readable value instead of regex-matching error
        // strings. Older registries that don't emit code: response will
        // have code === undefined; callers must fall back to error-string
        // classification in that case.
        return {
          valid: false,
          code: data?.code || null,
          error: data && (data.error?.message || data.error || data.reason) || "Registry did not confirm valid",
          agent_id: data?.agent_id || null,
        };
      }
      return {
        valid: true,
        agent_id: data.agent_id,
        operator_id: data.operator_id,
        status: data.status,
        expires_at: data.expires_at,
      };
    } catch (e) {
      // Transport / timeout errors throw; bad-token (4xx) responses convert
      // to {valid:false}. The distinction is the AxisError.code: anything
      // other than REGISTRY_UNREACHABLE / REGISTRY_HTTP is a 4xx the
      // registry produced about the token, which we treat as "not valid".
      if (e instanceof AxisError && e.code !== ERR.REGISTRY_UNREACHABLE) {
        return { valid: false, error: e.message };
      }
      throw e;
    }
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
   * @param {{proofValue: string, proofType?: string}} [opts.proof]  Optional Ed25519 proof of key
   *   ownership. v0.2+ proofs carry `proofType: "jcs-eddsa-2026"` (JCS canonicalization); the
   *   registry also accepts a proof with proofType absent (legacy v0.1 regime, JCS-first verify).
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
   * Per AXIS Protocol Spec v0.1 §4.4, the canonical Delegation Credential
   * timestamp fields are `created` and `expires`.
   *
   * @param {object} opts
   * @param {string} opts.issued_by                    Full axis id of the issuer (agent or operator)
   * @param {string} opts.issued_to                    Full axis id of the recipient
   * @param {string} opts.root_operator                Operator identity at the root of the delegation chain. For self-issued delegations (operator → its own agent) this defaults to issued_by. Per spec v0.1, must be byte-for-byte identical across every credential in a chain.
   * @param {string[]} opts.scope                      Non-empty array of scope tokens
   * @param {string} opts.expires                      ISO-8601 expiration timestamp
   * @param {object} [opts.constraints]                Optional constraints object
   * @param {string} [opts.parent_credential_id]       Optional parent delegation for attenuation
   * @param {string} [opts.signature]                  Optional signature over canonical body
   */
  async createDelegation({ issued_by, issued_to, root_operator, scope, expires, constraints, parent_credential_id, signature } = {}) {
    if (!issued_by) throw new AxisError(ERR.INVALID_INPUT, "issued_by is required");
    if (!issued_to) throw new AxisError(ERR.INVALID_INPUT, "issued_to is required");
    if (!Array.isArray(scope) || scope.length === 0) {
      throw new AxisError(ERR.INVALID_INPUT, "scope must be a non-empty array");
    }
    if (!expires) throw new AxisError(ERR.INVALID_INPUT, "expires is required");
    // root_operator is required by the registry per AXIS spec v0.1. For
    // self-issued delegations (operator → its own agent) it defaults to
    // issued_by; chained delegations must pass it explicitly to keep the
    // chain anchored to the same root.
    const effective_root = root_operator || issued_by;
    const body = { issued_by, issued_to, root_operator: effective_root, scope, expires };
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
    // v0.2+ (SDK v0.3): signCanonical now canonicalizes with RFC 8785 JCS, so
    // we advertise `proofType: "jcs-eddsa-2026"` on the wire. The registry
    // accepts both regimes (proofType absent ⇒ legacy, JCS-first), but sending
    // the proofType makes the registry take the JCS verification path
    // explicitly rather than relying on the legacy fall-through.
    const record = await this.registerAgent({
      operator,
      publicKey: keypair.publicKeyB64,
      metadata,
      service,
      proof: { proofType: "jcs-eddsa-2026", proofValue },
    });
    const agent_id = record.axis_id || record.did;
    // Surface operator_id at the top level of the session for ergonomic
    // access. The AXIS spec defines operator_id in the canonical
    // `axis:{slug}:operator` form. Two registry response shapes need
    // handling:
    //   - Newer registries: return `operator_id` top-level on /register
    //     in canonical form. Use as-is.
    //   - Older registries: nest the bare operator slug under
    //     `document.axisMetadata.operator.id` (e.g. "offworldnews-ai").
    //     Reconstruct the canonical form.
    let operator_id = record.operator_id ?? null;
    if (!operator_id) {
      const bareSlug = record.document?.axisMetadata?.operator?.id;
      if (bareSlug) {
        operator_id = `axis:${bareSlug}:operator`;
      }
    }
    // Also patch the record itself so callers reading `session.record.operator_id`
    // (which the AXIS spec defines as a top-level Agent Identity Record field)
    // see it regardless of which registry shape came back.
    if (operator_id && !record.operator_id) {
      record.operator_id = operator_id;
    }
    const sign = ({ ttl = 300, claims = {} } = {}) =>
      signAIT({ privateKey: keypair.privateKey, agentId: agent_id, ttl, claims });
    return {
      agent_id,
      did: record.did,
      axis_id: record.axis_id,
      operator_id,
      record,
      keypair,
      sign,
    };
  }
}
