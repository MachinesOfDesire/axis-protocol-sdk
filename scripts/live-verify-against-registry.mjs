// True end-to-end check: use THIS SDK's JCS + signDelegation to register agents
// and sign a delegation, POSTed to the live registry. Proves the SDK's signing
// output is accepted by the deployed registry (not just by its code in-process).
//
// Run: AXIS_REGISTRAR_KEY=... node scripts/live-verify-against-registry.mjs <operator-domain>
import { generateKeypair, signCanonical, signDelegation } from '../src/index.js';

const BASE = process.env.AXIS_REGISTRY_URL || 'https://registry.axisprime.ai';
const KEY = process.env.AXIS_REGISTRAR_KEY;
const OP_DOMAIN = process.argv[2];
if (!KEY || !OP_DOMAIN) { console.error('need AXIS_REGISTRAR_KEY + operator domain arg'); process.exit(1); }
const op = OP_DOMAIN.split('.').slice(0, -1).join('-');
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.log('  FAIL', m); } };
const post = (p, b) => fetch(BASE + p, { method: 'POST', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(b) });

async function register(name) {
  const kp = await generateKeypair();
  const body = { operator: { domain: OP_DOMAIN }, publicKey: kp.publicKeyB64, metadata: { name: `sdk-live-${name}-${Date.now()}` } };
  // SDK signs the JCS canonicalization of the body (minus proof) — this is what
  // registerAgent/createAgent do internally; done explicitly here for clarity.
  const proofValue = await signCanonical(kp.privateKey, body);
  const r = await post('/register', { ...body, proof: { proofType: 'jcs-eddsa-2026', proofValue } });
  const j = await r.json();
  if (r.status !== 201) throw new Error(`register ${name}: ${r.status} ${JSON.stringify(j)}`);
  return { privateKey: kp.privateKey, axisId: j.axis_id };
}

(async () => {
  console.log('SDK registration proof (JCS) -> live registry');
  const issuer = await register('issuer');
  ok(!!issuer.axisId, `registered issuer via SDK JCS proof -> ${issuer.axisId}`);
  const delegate = await register('delegate');
  ok(!!delegate.axisId, `registered delegate via SDK JCS proof -> ${delegate.axisId}`);

  console.log('SDK signDelegation -> live registry');
  const dc = {
    axis_version: '0.2', type: 'DelegationCredential', id: `dc:${op}:sdk-live-${Date.now()}`,
    issued_by: issuer.axisId, issued_to: delegate.axisId, root_operator: op,
    scope: ['article:draft'], created: new Date().toISOString(),
    expires: new Date(Date.now() + 7 * 86400000).toISOString(), revocable: true,
  };
  const signed = await signDelegation(issuer.privateKey, dc);
  const rd = await post('/delegations', signed);
  const jd = await rd.json();
  ok(rd.status === 201, `registry accepted SDK-signed delegation -> ${rd.status} ${jd.id || JSON.stringify(jd)}`);

  const chain = await (await fetch(`${BASE}/delegations/${encodeURIComponent(delegate.axisId)}/chain`)).json();
  const link = (chain.chain || []).find((c) => c.delegation === dc.id);
  ok(link && link.signatureValid === true, `chain reports signatureValid=true on the SDK-signed DC`);

  // cleanup
  await fetch(`${BASE}/delegations/${encodeURIComponent(jd.id)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }, body: '{"reason":"sdk live-verify cleanup"}' }).catch(() => {});

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e?.message ?? e); process.exit(1); });
