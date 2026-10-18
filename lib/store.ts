// In-memory prototype store. Restarting the server resets all data. NOT a production persistence layer.
import crypto from 'crypto';

export type Sev = 'Low' | 'Medium' | 'High' | 'Critical';
export type Status = 'New' | 'Acknowledged' | 'Investigating' | 'Resolved' | 'Rejected' | 'None';
export interface Ev { id: string; ts: number; ip: string; type: string; tokenId: string | null; rate: number; anomaly: number; risk: number; severity: Sev; webhook: 'Verified' | 'Rejected'; status: Status; signals: { honeytoken: number; traffic: number; intel: number; repeat: number }; reasons: string[]; intel: string; action: string; history: { ts: number; actor: string; action: string }[] }
export interface Cfg { weights: { honeytoken: number; traffic: number; intel: number; repeat: number }; alertThreshold: number; windowSec: number }

// Development-only fallback. Set HONEYSHIELD_SECRET in the environment for anything beyond local demo.
const SECRET = process.env.HONEYSHIELD_SECRET || 'dev-only-honeyshield-secret-NOT-FOR-PRODUCTION';
const hmac = (s: string) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const IPS = ['192.0.2.10', '198.51.100.24', '203.0.113.42'];
// SYNTHETIC threat intelligence (reserved documentation IPs). Not a live feed.
const INTEL: Record<string, { s: number; note: string }> = {
  '192.0.2.10': { s: 0.6, note: 'SYNTHETIC: listed in demo port-scanner list' },
  '198.51.100.24': { s: 0.8, note: 'SYNTHETIC: matches demo credential-stuffing list' },
  '203.0.113.42': { s: 0.9, note: 'SYNTHETIC: matches demo botnet-controller list' },
};
const DEF: Cfg = { weights: { honeytoken: 45, traffic: 25, intel: 15, repeat: 15 }, alertThreshold: 60, windowSec: 300 };
const sevOf = (r: number): Sev => (r >= 80 ? 'Critical' : r >= 60 ? 'High' : r >= 30 ? 'Medium' : 'Low');
const REC: Record<Sev, string> = {
  Critical: 'Isolate the decoy path, simulate an IP block, and open an investigation immediately.',
  High: 'Acknowledge the alert, start an investigation, and consider simulated rate limiting.',
  Medium: 'Monitor the source and review related events.',
  Low: 'No action required; retain for baseline.',
};

const TOKENS = () => [
  ['TOK-0001', 'employee_records.xlsx', 'Spreadsheet', '/shares/hr/archive/', 'Active', 'High'],
  ['TOK-0002', 'payroll_backup.csv', 'CSV', '/backups/finance/', 'Active', 'Critical'],
  ['TOK-0003', 'customer_database.json', 'JSON', '/db/exports/', 'Active', 'High'],
  ['TOK-0004', 'admin_credentials.txt', 'Text', '/admin/legacy/', 'Active', 'Critical'],
  ['TOK-0005', 'confidential_project.pdf', 'PDF', '/projects/restricted/', 'Monitoring', 'Medium'],
].map(([id, file, kind, location, status, risk]) => ({ id, file, kind, location, status, risk, count: 0, last: null as number | null }));

function fresh() {
  const s: any = { cfg: JSON.parse(JSON.stringify(DEF)), events: [] as Ev[], tokens: TOKENS(), hooks: [] as any[], seen: new Set<string>(), n: 1000, last: null };
  g.__hs = s;
  const m = 60000, now = Date.now();
  // [minutes ago, ip, type, token, requests/min, status override]
  const seed: any[] = [
    [700, '192.0.2.50', 'Normal Request', null, 10], [640, '198.51.100.77', 'Normal Request', null, 15],
    [560, '192.0.2.50', 'Normal Request', null, 12], [480, '192.0.2.10', 'Unusual Request Frequency', null, 140],
    [420, '198.51.100.77', 'Normal Request', null, 9], [360, '203.0.113.42', 'Threat Intel Match', null, 60],
    [300, '192.0.2.10', 'Honeytoken Access', 'TOK-0001', 90, 'Resolved'], [240, '198.51.100.24', 'Honeytoken Access', 'TOK-0003', 110, 'Investigating'],
    [200, '192.0.2.50', 'Normal Request', null, 11], [170, '198.51.100.24', 'Repeated Suspicious Access', 'TOK-0003', 150, 'Acknowledged'],
    [120, '203.0.113.42', 'Honeytoken Access', 'TOK-0004', 180], [90, '198.51.100.24', 'Invalid Webhook', null, 0, 'REJ', 'HMAC signature mismatch; payload discarded'],
    [75, '203.0.113.42', 'Repeated Suspicious Access', 'TOK-0004', 190], [50, '192.0.2.50', 'Normal Request', null, 14],
    [35, '198.51.100.24', 'Duplicate Event Rejected', 'TOK-0003', 0, 'REJ', 'Event ID already processed; replay protection rejected it'],
    [20, '192.0.2.10', 'Unusual Request Frequency', null, 170], [8, '198.51.100.77', 'Normal Request', null, 13],
  ];
  for (const [ago, ip, type, tokenId, rate, st, why] of seed)
    mk({ ts: now - ago * m, ip, type, tokenId, rate, rejected: st === 'REJ' ? why : undefined, force: st && st !== 'REJ' ? st : undefined });
  return s;
}
const g = globalThis as any;
export const S = () => g.__hs || fresh();
const nid = () => `EVT-${++S().n}`;

export function score(cfg: Cfg, p: { token: boolean; rate: number; ip: string; rep: number }) {
  const sig = { honeytoken: p.token ? 1 : 0, traffic: Math.min(1, p.rate / 200), intel: INTEL[p.ip]?.s ?? 0, repeat: Math.min(1, p.rep / 3) };
  const w = cfg.weights, tot = w.honeytoken + w.traffic + w.intel + w.repeat || 1;
  const risk = Math.max(0, Math.min(100, Math.round(((w.honeytoken * sig.honeytoken + w.traffic * sig.traffic + w.intel * sig.intel + w.repeat * sig.repeat) / tot) * 100)));
  const reasons: string[] = [];
  if (p.token) reasons.push(`Honeytoken decoy was accessed (signal 1.00, weight ${w.honeytoken}). Legitimate users have no reason to touch decoys.`);
  if (sig.traffic >= 0.4) reasons.push(`Request rate ${p.rate}/min is elevated vs. 200/min saturation (signal ${sig.traffic.toFixed(2)}, weight ${w.traffic}).`);
  if (sig.intel > 0) reasons.push(`${INTEL[p.ip].note} (signal ${sig.intel.toFixed(2)}, weight ${w.intel}).`);
  if (p.rep > 0) reasons.push(`${p.rep} prior decoy access(es) from this IP within 15 min (signal ${sig.repeat.toFixed(2)}, weight ${w.repeat}).`);
  if (!reasons.length) reasons.push('No honeytoken access, normal request rate, no synthetic intel match.');
  return { sig, risk, anomaly: Math.round(sig.traffic * 100), reasons };
}

function mk(o: { id?: string; ts?: number; ip: string; type: string; tokenId?: string | null; rate: number; rejected?: string; force?: string }): Ev {
  const s = S(), ts = o.ts ?? Date.now(), tokenId = o.tokenId ?? null;
  const rep = tokenId && !o.rejected ? s.events.filter((e: Ev) => e.ip === o.ip && e.tokenId && e.webhook === 'Verified' && ts - e.ts < 15 * 60000 && e.ts <= ts).length : 0;
  const sc = score(s.cfg, { token: !!tokenId, rate: o.rate, ip: o.ip, rep });
  const rej = !!o.rejected, risk = rej ? 0 : sc.risk, severity = sevOf(risk);
  const status: Status = rej ? 'Rejected' : risk >= s.cfg.alertThreshold ? 'New' : 'None';
  const ev: Ev = {
    id: o.id || nid(), ts, ip: o.ip, type: o.type, tokenId, rate: o.rate, anomaly: rej ? 0 : sc.anomaly, risk, severity, webhook: rej ? 'Rejected' : 'Verified', status,
    signals: sc.sig, reasons: rej ? [o.rejected!] : sc.reasons, intel: INTEL[o.ip]?.note || 'SYNTHETIC: no match in demo intel list', action: REC[severity],
    history: [{ ts, actor: 'system', action: rej ? 'Webhook rejected; no incident created' : `Event ingested; signature verified` }],
  };
  if (status === 'New') ev.history.push({ ts, actor: 'risk-engine', action: `Alert created (risk ${risk} ≥ threshold ${s.cfg.alertThreshold})` });
  if (o.force && status !== 'None') {
    ev.status = o.force as Status;
    ev.history.push({ ts: ts + 120000, actor: 'analyst', action: `Status set to ${o.force}` });
  }
  s.events.push(ev);
  const t = s.tokens.find((x: any) => x.id === tokenId);
  if (t && !rej) { t.count++; t.last = ts; }
  return ev;
}

export function signed(tokenId: string | null, ip: string, type: string) {
  const payload = JSON.stringify({ eventId: nid(), tokenId, timestamp: Date.now(), sourceIp: ip, eventType: type });
  return { payload, signature: hmac(payload) };
}

export function receive(raw: string, sig: string, kind: string, dry = false) {
  const s = S();
  let p: any = {}, parsed = true;
  try { p = JSON.parse(raw); } catch { parsed = false; }
  const a = Buffer.from(sig || '', 'hex'), b = Buffer.from(hmac(raw), 'hex');
  const sigOk = parsed && a.length === b.length && crypto.timingSafeEqual(a, b);
  const timeOk = parsed && Math.abs(Date.now() - Number(p.timestamp)) <= s.cfg.windowSec * 1000;
  const replay = parsed && s.seen.has(p.eventId);
  let result = 'Accepted: security event created', event: Ev | null = null;
  if (!sigOk) result = 'REJECTED: invalid signature (HMAC-SHA256 mismatch)';
  else if (!timeOk) result = `REJECTED: timestamp outside ±${s.cfg.windowSec}s window`;
  else if (replay) result = 'REJECTED: duplicate event ID (replay protection)';
  else if (dry) result = 'Dry run: signature and timestamp valid; no event created';
  else {
    s.seen.add(p.eventId);
    const tok = s.tokens.find((t: any) => t.id === p.tokenId);
    event = mk({ id: p.eventId, ip: p.sourceIp, type: p.eventType, tokenId: p.tokenId, rate: tok ? Math.min(200, 70 + 35 * tok.count) : 40 });
  }
  const hook = { ts: Date.now(), kind, eventId: p.eventId || '(unparseable)', payload: raw, signature: sig, sig: sigOk, time: timeOk, replay, result };
  s.hooks.unshift(hook);
  s.hooks.length = Math.min(s.hooks.length, 50);
  return { hook, event };
}

export function accessToken(id: string) {
  const s = S(), i = s.tokens.findIndex((t: any) => t.id === id);
  if (i < 0) return null;
  const t = s.tokens[i];
  const { payload, signature } = signed(t.id, IPS[i % 3], t.count >= 2 ? 'Repeated Suspicious Access' : 'Honeytoken Access');
  s.last = { payload, signature };
  return receive(payload, signature, 'Simulate Access');
}

export function webhookAction(action: string) {
  const s = S();
  if (action === 'generate') {
    const x = signed(null, '192.0.2.50', 'Webhook Test Event');
    s.last = x;
    return receive(x.payload, x.signature, 'Generate Test Event');
  }
  if (action === 'invalid') {
    const x = signed('TOK-0002', '198.51.100.24', 'Honeytoken Access');
    return receive(x.payload.replace('"TOK-0002"', '"TOK-0001"'), x.signature, 'Simulate Invalid Signature'); // payload tampered after signing
  }
  if (!s.last) return { error: 'No prior event. Click Generate Test Event first.' };
  if (action === 'verify') return receive(s.last.payload, s.last.signature, 'Verify Signature', true);
  if (action === 'duplicate') return receive(s.last.payload, s.last.signature, 'Simulate Duplicate Event');
  return { error: 'Unknown action' };
}

export function act(id: string, action: string, confirm: boolean) {
  const e: Ev | undefined = S().events.find((x: Ev) => x.id === id);
  if (!e) return { code: 404, error: 'Event not found' };
  if (e.status === 'None' || e.status === 'Rejected') return { code: 409, error: 'This event is not an incident' };
  const log = (a: string) => e.history.push({ ts: Date.now(), actor: 'analyst', action: a });
  if (action === 'acknowledge') { if (e.status !== 'New') return { code: 409, error: `Cannot acknowledge an incident that is ${e.status}` }; e.status = 'Acknowledged'; log('Alert acknowledged'); }
  else if (action === 'investigate') { if (!['New', 'Acknowledged'].includes(e.status)) return { code: 409, error: `Cannot start investigating from ${e.status}` }; e.status = 'Investigating'; log('Marked investigating'); }
  else if (action === 'resolve') { if (e.status === 'Resolved') return { code: 409, error: 'Already resolved' }; e.status = 'Resolved'; log('Incident resolved'); }
  else if (action === 'ratelimit' || action === 'block') {
    if (e.status === 'Resolved') return { code: 409, error: 'Cannot respond to a resolved incident' };
    if (action === 'block' && !confirm) return { code: 400, error: 'IP block requires confirmation' };
    log(action === 'block' ? `SIMULATED IP block of ${e.ip} (demo only; no firewall changed)` : `SIMULATED rate limit for ${e.ip} (demo only; no traffic affected)`);
  } else return { code: 400, error: 'Unknown action' };
  return { code: 200, event: e };
}

export function setConfig(b: any) {
  const s = S(), w = b?.weights;
  const num = (v: any, lo: number, hi: number) => typeof v === 'number' && isFinite(v) && v >= lo && v <= hi;
  if (!w || !['honeytoken', 'traffic', 'intel', 'repeat'].every(k => num(w[k], 0, 100)) || !num(b.alertThreshold, 0, 100) || !num(b.windowSec, 10, 3600)) return false;
  s.cfg = { weights: { honeytoken: w.honeytoken, traffic: w.traffic, intel: w.intel, repeat: w.repeat }, alertThreshold: b.alertThreshold, windowSec: b.windowSec };
  return true;
}
export const reset = () => { fresh(); };

export function state() {
  const s = S(), ev: Ev[] = [...s.events].sort((a, b) => b.ts - a.ts), now = Date.now();
  const ok = ev.filter(e => e.webhook === 'Verified');
  const series = Array.from({ length: 12 }, (_, k) => {
    const st = now - (12 - k) * 3600000, inB = (e: Ev) => e.ts >= st && e.ts < st + 3600000;
    return { hour: `${String(new Date(st).getHours()).padStart(2, '0')}:00`, events: ev.filter(inB).length, high: ok.filter(e => inB(e) && e.risk >= 60).length };
  });
  const cat: Record<string, number> = {};
  ev.forEach(e => (cat[e.type] = (cat[e.type] || 0) + 1));
  return {
    events: ev, tokens: s.tokens, hooks: s.hooks, cfg: s.cfg, now,
    stats: {
      total: ev.length, triggers: ok.filter(e => e.tokenId).length, high: ok.filter(e => e.risk >= 60).length,
      open: ev.filter(e => ['New', 'Acknowledged', 'Investigating'].includes(e.status)).length,
      series, dist: (['Low', 'Medium', 'High', 'Critical'] as Sev[]).map(n => ({ name: n, value: ok.filter(e => e.severity === n).length })),
      cats: Object.entries(cat).map(([name, value]) => ({ name, value })),
    },
  };
}
