'use client';
import { useCallback, useEffect, useState } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, CartesianGrid } from 'recharts';
import { Shield, LayoutDashboard, KeyRound, List as ListIcon, Gauge, Webhook, Siren, Settings as Cog, Bell, PanelLeft, Copy, Play, X, Loader2 } from 'lucide-react';

const TABS: [string, any][] = [['Overview', LayoutDashboard], ['Honeytoken Vault', KeyRound], ['Threat Events', ListIcon], ['Risk Analysis', Gauge], ['Webhook Inspector', Webhook], ['Incident Response', Siren], ['Settings', Cog]];
const G = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', A = 'bg-amber-500/15 text-amber-400 border-amber-500/30', R = 'bg-red-500/15 text-red-400 border-red-500/30', O = 'bg-orange-500/15 text-orange-400 border-orange-500/30', C = 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30', N = 'bg-slate-500/15 text-slate-400 border-slate-500/30';
const COL: any = { Low: G, Medium: A, High: O, Critical: R, Verified: G, Rejected: R, New: R, Acknowledged: A, Investigating: C, Resolved: G, None: N, Active: G, Monitoring: A };
const SEVC: any = { Low: '#10b981', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
const fmt = (t: number | null) => (t ? new Date(t).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—');
async function api(path: string, method = 'GET', body?: any) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { ok: r.ok, data: await r.json().catch(() => ({})) };
}
const Badge = ({ v }: any) => <span className={`whitespace-nowrap rounded border px-2 py-0.5 text-xs font-medium ${COL[v] || N}`}>{v}</span>;
const Card = ({ t, children, c = '' }: any) => <section className={`rounded-lg border border-slate-800 bg-slate-900/70 p-4 ${c}`}>{t && <h3 className="mb-3 text-sm font-semibold text-slate-200">{t}</h3>}{children}</section>;
const Btn = ({ children, onClick, disabled, v = 'p' }: any) => <button disabled={disabled} onClick={onClick} className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium disabled:opacity-40 ${v === 'd' ? 'border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20' : v === 's' ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700' : 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20'}`}>{children}</button>;
const sel = 'rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-200';

function ETable({ rows, full, onRow }: any) {
  const H = full ? ['Timestamp', 'Event ID', 'Source IP', 'Type', 'Token', 'Anomaly', 'Risk', 'Severity', 'Webhook', 'Status'] : ['Timestamp', 'Event ID', 'Source IP', 'Type', 'Risk', 'Severity', 'Status'];
  return <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-slate-400"><tr>{H.map(h => <th key={h} className="whitespace-nowrap px-2 py-2 font-medium">{h}</th>)}</tr></thead><tbody>
    {rows.map((e: any) => <tr key={e.id} onClick={() => onRow(e.id)} className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/60">
      <td className="whitespace-nowrap px-2 py-2 text-slate-400">{fmt(e.ts)}</td><td className="px-2 py-2 font-mono text-cyan-300">{e.id}</td><td className="px-2 py-2 font-mono">{e.ip}</td><td className="whitespace-nowrap px-2 py-2">{e.type}</td>
      {full && <><td className="px-2 py-2 font-mono">{e.tokenId || '—'}</td><td className="px-2 py-2">{e.anomaly}</td></>}
      <td className="px-2 py-2 font-semibold">{e.risk}</td><td className="px-2 py-2"><Badge v={e.severity} /></td>{full && <td className="px-2 py-2"><Badge v={e.webhook} /></td>}<td className="px-2 py-2"><Badge v={e.status} /></td></tr>)}
    {!rows.length && <tr><td colSpan={H.length} className="px-2 py-6 text-center text-slate-500">No matching events</td></tr>}
  </tbody></table></div>;
}

function Detail({ e, onAct }: any) {
  const Row = ([k, v]: any) => <div key={k} className="flex justify-between gap-3 border-b border-slate-800 py-1.5 text-xs"><span className="text-slate-400">{k}</span><span className="break-all text-right font-mono">{v}</span></div>;
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-lg text-cyan-300">{e.id}</span><Badge v={e.severity} /><Badge v={e.status} /></div>
    <div>{[['Timestamp', fmt(e.ts)], ['Source IP (reserved)', e.ip], ['Type', e.type], ['Token', e.tokenId || '—'], ['Request rate', `${e.rate}/min`], ['Anomaly score', e.anomaly], ['Risk score', e.risk], ['Webhook verification', e.webhook === 'Verified' ? 'Verified on server (HMAC-SHA256)' : 'Rejected on server']].map(Row)}</div>
    <div><h4 className="mb-1 text-xs font-semibold text-slate-300">Detection reasons</h4><ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">{e.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}</ul></div>
    <div><h4 className="mb-1 text-xs font-semibold text-slate-300">Threat intelligence (synthetic)</h4><p className="text-xs text-slate-300">{e.intel}</p></div>
    <div><h4 className="mb-1 text-xs font-semibold text-slate-300">Recommended response</h4><p className="text-xs text-slate-300">{e.action}</p></div>
    {onAct && !['None', 'Rejected'].includes(e.status) && <div className="flex flex-wrap gap-2">
      <Btn onClick={() => onAct(e.id, 'acknowledge')} disabled={e.status !== 'New'}>Acknowledge Alert</Btn><Btn onClick={() => onAct(e.id, 'investigate')} disabled={!['New', 'Acknowledged'].includes(e.status)}>Mark Investigating</Btn>
      <Btn onClick={() => onAct(e.id, 'resolve')} disabled={e.status === 'Resolved'}>Resolve Incident</Btn><Btn v="s" onClick={() => onAct(e.id, 'ratelimit')} disabled={e.status === 'Resolved'}>Simulate Rate Limit</Btn>
      <Btn v="d" onClick={() => onAct(e.id, 'block')} disabled={e.status === 'Resolved'}>Simulate IP Block</Btn></div>}
    <div><h4 className="mb-1 text-xs font-semibold text-slate-300">Incident action history</h4><ul className="space-y-1 text-xs">{e.history.map((h: any, i: number) => <li key={i} className="rounded border border-slate-800 bg-slate-950/50 px-2 py-1"><span className="text-slate-500">{fmt(h.ts)}</span> <span className="text-cyan-400">{h.actor}</span>: {h.action}</li>)}</ul></div>
  </div>;
}

// ── View components lifted to module scope so their identity is stable across re-renders ──

function Overview({ ev, st, goto }: { ev: any[]; st: any; goto: (id: string) => void }) {
  return <div className="space-y-4">
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[['Total Security Events', st.total, 'text-cyan-300'], ['Honeytoken Triggers', st.triggers, 'text-amber-300'], ['High-Risk Alerts', st.high, 'text-red-400'], ['Open Incidents', st.open, 'text-orange-300']].map(([k, v, c]: any) => <Card key={k}><div className="text-xs text-slate-400">{k}</div><div className={`mt-1 text-3xl font-semibold ${c}`}>{v}</div></Card>)}</div>
    <div className="grid gap-4 lg:grid-cols-3">
      <Card t="Security events over time (last 12h)" c="lg:col-span-2"><div className="h-60"><ResponsiveContainer><LineChart data={st.series}><CartesianGrid stroke="#1e293b" /><XAxis dataKey="hour" stroke="#64748b" fontSize={11} /><YAxis stroke="#64748b" fontSize={11} allowDecimals={false} /><Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} /><Line dataKey="events" name="All events" stroke="#22d3ee" strokeWidth={2} dot={false} /><Line dataKey="high" name="High-risk" stroke="#ef4444" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div></Card>
      <Card t="Risk distribution"><div className="h-60"><ResponsiveContainer><PieChart><Pie data={st.dist} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>{st.dist.map((d: any) => <Cell key={d.name} fill={SEVC[d.name]} stroke="none" />)}</Pie><Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} /></PieChart></ResponsiveContainer></div><div className="flex flex-wrap justify-center gap-3 text-xs">{st.dist.map((d: any) => <span key={d.name} className="flex items-center gap-1"><i className="h-2 w-2 rounded-full" style={{ background: SEVC[d.name] }} />{d.name} {d.value}</span>)}</div></Card>
    </div>
    <div className="grid gap-4 lg:grid-cols-3">
      <Card t="Detection sources / categories"><div className="h-56"><ResponsiveContainer><BarChart data={st.cats} layout="vertical" margin={{ left: 40 }}><XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} /><YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={130} /><Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155' }} /><Bar dataKey="value" fill="#3b82f6" radius={3} /></BarChart></ResponsiveContainer></div></Card>
      <Card t="Recent activity"><ul className="space-y-2 text-xs">{ev.slice(0, 6).map(e => <li key={e.id} onClick={() => goto(e.id)} className="cursor-pointer rounded border border-slate-800 p-2 hover:bg-slate-800/60"><div className="flex justify-between"><span className="font-mono text-cyan-300">{e.id}</span><Badge v={e.severity} /></div><div className="mt-1 text-slate-300">{e.type} from {e.ip}</div><div className="text-slate-500">{fmt(e.ts)}</div></li>)}</ul></Card>
      <Card t="System health (local prototype)"><ul className="space-y-2 text-xs">{[['Event processing', 'Operational', G], ['Webhook verification', 'Operational', G], ['Risk engine (simulated, deterministic)', 'Operational', G], ['Threat intelligence', 'DEMO DATA', A]].map(([k, v, c]) => <li key={k} className="flex items-center justify-between"><span className="text-slate-300">{k}</span><span className={`rounded border px-2 py-0.5 ${c}`}>{v}</span></li>)}</ul><p className="mt-3 text-xs text-slate-500">Indicators describe this local in-memory prototype, not external monitoring.</p></Card>
    </div>
    <Card t="Recent events"><ETable rows={ev.slice(0, 8)} onRow={goto} /></Card>
  </div>;
}

function Vault({ S, ev, notify, load }: { S: any; ev: any[]; notify: (msg: string, ok?: boolean, goto?: string) => void; load: () => void }) {
  const [busy, setBusy] = useState<string | null>(null), [open, setOpen] = useState<string | null>(null);
  const run = async (id: string) => {
    setBusy(id); const r = await api(`/api/tokens/${id}/access`, 'POST'); setBusy(null);
    if (r.ok) { const e = r.data.event; notify(`Access simulated: ${e.id} created, risk ${e.risk} (${e.severity}), signature verified`, true, e.id); } else notify(r.data.error || 'Failed', false);
    load();
  };
  return <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{S.tokens.map((t: any) => <Card key={t.id}>
    <div className="flex items-start justify-between"><div><div className="font-mono text-sm text-cyan-300">{t.file}</div><div className="text-xs text-slate-500">{t.id} · {t.kind} (synthetic)</div></div><Badge v={t.risk} /></div>
    <div className="mt-3 space-y-1 text-xs text-slate-300"><div>Location: <span className="font-mono">{t.location}</span></div><div className="flex items-center gap-2">Status <Badge v={t.status} /></div><div>Access count: <b>{t.count}</b></div><div>Last triggered: {fmt(t.last)}</div></div>
    {open === t.id && <div className="mt-3 rounded border border-slate-800 bg-slate-950/50 p-2 text-xs text-slate-400">Synthetic decoy. Contains no real data. Any access is treated as suspicious. Recent events: {ev.filter(e => e.tokenId === t.id).slice(0, 3).map(e => e.id).join(', ') || 'none'}</div>}
    <div className="mt-3 flex flex-wrap gap-2"><Btn v="s" onClick={() => setOpen(open === t.id ? null : t.id)}>View Details</Btn><Btn onClick={() => run(t.id)} disabled={!!busy}>{busy === t.id ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}{busy === t.id ? 'Processing…' : 'Simulate Access'}</Btn><Btn v="s" onClick={() => { navigator.clipboard?.writeText(t.id); notify(`Copied ${t.id}`); }}><Copy size={12} />Copy Token ID</Btn></div>
  </Card>)}</div>;
}

function Events({ ev, setSel }: { ev: any[]; setSel: (id: string | null) => void }) {
  const [q, setQ] = useState(''), [sv, setSv] = useState(''), [ty, setTy] = useState(''), [stt, setStt] = useState(''), [sort, setSort] = useState('ts');
  const types = Array.from(new Set(ev.map(e => e.type)));
  const rows = ev.filter(e => (!q || [e.id, e.ip, e.tokenId || ''].some(x => x.toLowerCase().includes(q.toLowerCase()))) && (!sv || e.severity === sv) && (!ty || e.type === ty) && (!stt || e.status === stt)).sort((a, b) => (sort === 'risk' ? b.risk - a.risk : b.ts - a.ts));
  return <Card><div className="mb-3 flex flex-wrap gap-2"><input className={`${sel} w-52`} placeholder="Search event ID, IP, token" value={q} onChange={e => setQ(e.target.value)} />
    <select className={sel} value={sv} onChange={e => setSv(e.target.value)}><option value="">All severities</option>{['Low', 'Medium', 'High', 'Critical'].map(x => <option key={x}>{x}</option>)}</select>
    <select className={sel} value={ty} onChange={e => setTy(e.target.value)}><option value="">All types</option>{types.map(x => <option key={x}>{x}</option>)}</select>
    <select className={sel} value={stt} onChange={e => setStt(e.target.value)}><option value="">All statuses</option>{['New', 'Acknowledged', 'Investigating', 'Resolved', 'Rejected', 'None'].map(x => <option key={x}>{x}</option>)}</select>
    <select className={sel} value={sort} onChange={e => setSort(e.target.value)}><option value="ts">Sort: newest</option><option value="risk">Sort: risk score</option></select></div><ETable full rows={rows} onRow={setSel} /></Card>;
}

function Risk({ ev, S }: { ev: any[]; S: any }) {
  const [id, setId] = useState<string>(ev.find(e => e.webhook === 'Verified')?.id);
  const e = ev.find(x => x.id === id) || ev[0], w = S.cfg.weights, tot = w.honeytoken + w.traffic + w.intel + w.repeat || 1;
  const rows = (['honeytoken', 'traffic', 'intel', 'repeat'] as const).map(k => ({ k, v: e.signals[k], w: w[k], pts: (w[k] * e.signals[k]) / tot * 100 }));
  return <div className="space-y-4"><Card><div className="rounded border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-300">Simulated, deterministic anomaly-scoring engine. This is NOT a trained ML model; the scoring module is structured so a trained model can replace it later.</div>
    <p className="mt-3 text-xs text-slate-400">risk = Σ(weight × signal) ÷ Σ(weights) × 100, clamped to 0–100. Severity: 0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical.</p>
    <select className={`${sel} mt-3`} value={e.id} onChange={x => setId(x.target.value)}>{ev.map(x => <option key={x.id} value={x.id}>{x.id} · {x.type} · risk {x.risk}</option>)}</select></Card>
    <div className="grid gap-4 lg:grid-cols-2"><Card t={`Signal breakdown for ${e.id}`}>{rows.map(r => <div key={r.k} className="mb-3 text-xs"><div className="flex justify-between"><span className="capitalize text-slate-300">{r.k} signal {r.v.toFixed(2)} × weight {r.w}</span><span>+{r.pts.toFixed(1)} pts</span></div><div className="mt-1 h-2 rounded bg-slate-800"><div className="h-2 rounded bg-cyan-400" style={{ width: `${Math.min(100, r.pts * 2)}%` }} /></div></div>)}
      <div className="mt-2 flex items-center gap-3 border-t border-slate-800 pt-3 text-sm">Anomaly score <b>{e.anomaly}</b> · Final risk <b>{e.risk}</b> <Badge v={e.severity} /></div></Card>
      <Card t="Why this score"><ul className="list-disc space-y-1 pl-4 text-xs text-slate-300">{e.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}</ul><p className="mt-3 text-xs text-slate-300"><b>Next action:</b> {e.action}</p></Card></div></div>;
}

function Hooks({ S, notify, load }: { S: any; notify: (msg: string, ok?: boolean, goto?: string) => void; load: () => void }) {
  const [busy, setBusy] = useState(''), [last, setLast] = useState<any>(S.hooks[0]);
  const run = async (a: string, label: string) => {
    setBusy(a); const r = await api('/api/webhook', 'POST', { action: a }); setBusy('');
    if (r.data.hook) { setLast(r.data.hook); notify(`${label}: ${r.data.hook.result}`, !r.data.hook.result.startsWith('REJECTED') || a !== 'generate'); } else notify(r.data.error, false);
    load();
  };
  const B = [['generate', 'Generate Test Event'], ['verify', 'Verify Signature'], ['invalid', 'Simulate Invalid Signature'], ['duplicate', 'Simulate Duplicate Event']];
  const Chk = ({ ok, l }: any) => <span className={`rounded border px-2 py-0.5 text-xs ${ok ? G : R}`}>{l}: {ok ? 'pass' : 'fail'}</span>;
  return <div className="space-y-4"><Card><div className="flex flex-wrap gap-2">{B.map(([a, l]) => <Btn key={a} v={a === 'invalid' || a === 'duplicate' ? 'd' : 'p'} disabled={!!busy} onClick={() => run(a, l)}>{busy === a && <Loader2 size={12} className="animate-spin" />}{l}</Btn>)}</div><p className="mt-2 text-xs text-slate-500">All checks run server-side. The signing secret never reaches the browser.</p></Card>
    {last && <Card t={`Latest: ${last.kind}`}><div className="space-y-2 text-xs"><div className="flex flex-wrap gap-2"><Chk ok={last.sig} l="Signature" /><Chk ok={last.time} l="Timestamp" /><Chk ok={!last.replay} l="Replay check" /></div><div className={last.result.startsWith('REJECTED') ? 'text-red-400' : 'text-emerald-400'}>{last.result}</div><div className="text-slate-400">Payload</div><pre className="overflow-x-auto rounded bg-slate-950 p-2 font-mono text-cyan-200">{last.payload}</pre><div className="text-slate-400">HMAC-SHA256 signature</div><pre className="overflow-x-auto rounded bg-slate-950 p-2 font-mono text-slate-300">{last.signature}</pre></div></Card>}
    <Card t="Verification log"><div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-slate-400"><tr>{['Time', 'Test', 'Event ID', 'Sig', 'Time', 'Replay', 'Result'].map((h, i) => <th key={i} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead><tbody>{S.hooks.map((h: any, i: number) => <tr key={i} className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/60" onClick={() => setLast(h)}><td className="whitespace-nowrap px-2 py-2 text-slate-400">{fmt(h.ts)}</td><td className="px-2 py-2">{h.kind}</td><td className="px-2 py-2 font-mono">{h.eventId}</td><td className="px-2 py-2">{h.sig ? '✓' : '✗'}</td><td className="px-2 py-2">{h.time ? '✓' : '✗'}</td><td className="px-2 py-2">{h.replay ? 'seen' : 'new'}</td><td className="px-2 py-2">{h.result}</td></tr>)}{!S.hooks.length && <tr><td colSpan={7} className="px-2 py-6 text-center text-slate-500">No webhook activity yet. Generate a test event.</td></tr>}</tbody></table></div></Card></div>;
}

function Incidents({ ev, act, pick, setPick }: { ev: any[]; act: (id: string, action: string) => void; pick: string | null; setPick: (id: string | null) => void }) {
  const [sv, setSv] = useState(''), [stt, setStt] = useState('');
  const inc = ev.filter(e => !['None', 'Rejected'].includes(e.status) && (!sv || e.severity === sv) && (!stt || e.status === stt));
  const cur = ev.find(e => e.id === pick && !['None', 'Rejected'].includes(e.status)) || inc[0];
  return <div className="grid gap-4 lg:grid-cols-5"><Card t="Incident queue" c="lg:col-span-2"><div className="mb-3 flex gap-2"><select className={sel} value={sv} onChange={e => setSv(e.target.value)}><option value="">All severities</option>{['Medium', 'High', 'Critical'].map(x => <option key={x}>{x}</option>)}</select><select className={sel} value={stt} onChange={e => setStt(e.target.value)}><option value="">All statuses</option>{['New', 'Acknowledged', 'Investigating', 'Resolved'].map(x => <option key={x}>{x}</option>)}</select></div>
    <ul className="max-h-[70vh] space-y-2 overflow-y-auto">{inc.map(e => <li key={e.id} onClick={() => setPick(e.id)} className={`cursor-pointer rounded border p-2 text-xs hover:bg-slate-800/60 ${cur?.id === e.id ? 'border-cyan-500/50 bg-slate-800/60' : 'border-slate-800'}`}><div className="flex justify-between"><span className="font-mono text-cyan-300">{e.id}</span><span className="flex gap-1"><Badge v={e.severity} /><Badge v={e.status} /></span></div><div className="mt-1 text-slate-300">{e.type} · {e.ip} · risk {e.risk}</div></li>)}{!inc.length && <li className="py-6 text-center text-xs text-slate-500">No incidents match</li>}</ul></Card>
    <Card t="Incident details" c="lg:col-span-3">{cur ? <Detail e={cur} onAct={act} /> : <p className="text-xs text-slate-500">Select an incident.</p>}</Card></div>;
}

function Settings({ S, notify, load }: { S: any; notify: (msg: string, ok?: boolean, goto?: string) => void; load: () => void }) {
  const [c, setC] = useState<any>(JSON.parse(JSON.stringify(S.cfg))), [prefs, setPrefs] = useState<any>({ Critical: true, High: true, Medium: false, Low: false });
  const setW = (k: string, v: number) => setC({ ...c, weights: { ...c.weights, [k]: v } });
  const save = async () => { const r = await api('/api/config', 'PUT', c); notify(r.ok ? 'Scoring configuration saved (applies to new events)' : r.data.error, r.ok); load(); };
  const reset = async () => { if (!window.confirm('Reset all demo data to the initial synthetic state?')) return; await api('/api/reset', 'POST'); notify('Demo data reset'); load(); };
  const Sl = ({ l, v, on, max = 100, min = 0 }: any) => <label className="block text-xs text-slate-300"><div className="flex justify-between"><span>{l}</span><b>{v}</b></div><input type="range" min={min} max={max} value={v} onChange={e => on(+e.target.value)} className="w-full accent-cyan-400" /></label>;
  return <div className="grid gap-4 lg:grid-cols-2">
    <Card t="Risk scoring (stored in server memory)"><div className="space-y-3"><Sl l="Alert threshold (risk ≥ creates incident)" v={c.alertThreshold} on={(v: number) => setC({ ...c, alertThreshold: v })} />{Object.keys(c.weights).map(k => <Sl key={k} l={`Weight: ${k}`} v={c.weights[k]} on={(v: number) => setW(k, v)} />)}<Sl l="Webhook timestamp window (seconds)" v={c.windowSec} min={10} max={3600} on={(v: number) => setC({ ...c, windowSec: v })} /><Btn onClick={save}>Save configuration</Btn></div></Card>
    <div className="space-y-4"><Card t="Alert severity preferences (interface only, not persisted)">{Object.keys(prefs).map(k => <label key={k} className="mr-4 inline-flex items-center gap-1 text-xs"><input type="checkbox" checked={prefs[k]} onChange={e => setPrefs({ ...prefs, [k]: e.target.checked })} />{k}</label>)}</Card>
      <Card t="Status"><ul className="space-y-1 text-xs text-slate-300"><li>Demo mode: <b className="text-amber-300">ON</b> (read-only indicator)</li><li>Webhook verification: <b className="text-emerald-400">Enforced server-side</b></li><li>Threat-intelligence mode: <b className="text-amber-300">Synthetic demo data</b></li><li>Data store: server memory only; restarting the server resets everything. Not a production persistence layer.</li></ul></Card>
      <Card t="Reset"><Btn v="d" onClick={reset}>Reset Demo Data</Btn></Card></div></div>;
}

// ── Root component ──────────────────────────────────────────────────────────

export default function Home() {
  const [S, setS] = useState<any>(null), [tab, setTab] = useState('Overview'), [sel_, setSel] = useState<string | null>(null), [toast, setToast] = useState<any>(null), [col, setCol] = useState(false), [pick, setPick] = useState<string | null>(null);
  const load = useCallback(async () => { try { const r = await api('/api/state'); if (r.ok) setS(r.data); } catch {} }, []);
  useEffect(() => { load(); const t = setInterval(load, 3000); return () => clearInterval(t); }, [load]);
  const notify = (msg: string, ok = true, goto?: string) => { setToast({ msg, ok, goto }); setTimeout(() => setToast(null), 7000); };
  const act = async (id: string, action: string) => {
    if (action === 'block' && !window.confirm('Simulate an IP block? Demo only: no real firewall or traffic is changed.')) return;
    const r = await api(`/api/incidents/${id}`, 'POST', { action, confirm: action === 'block' });
    notify(r.ok ? `${id}: ${action} recorded in audit trail` : r.data.error, r.ok); load();
  };
  if (!S) return <div className="flex h-screen items-center justify-center text-slate-400"><Loader2 className="mr-2 animate-spin" />Loading HoneyShield…</div>;
  const ev: any[] = S.events, st = S.stats, drawer = ev.find(e => e.id === sel_);
  const goto = (id: string) => { setTab('Threat Events'); setSel(id); setToast(null); };

  return <div className="flex h-screen flex-col">
    <header className="flex items-center gap-3 border-b border-slate-800 bg-slate-950/80 px-4 py-2.5">
      <button className="hidden text-slate-400 hover:text-white md:block" onClick={() => setCol(!col)}><PanelLeft size={18} /></button>
      <Shield className="text-cyan-400" size={22} /><div className="font-semibold tracking-wide">HoneyShield</div>
      <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">DEMO MODE</span>
      <div className="ml-auto flex items-center gap-4 text-xs"><span className="hidden items-center gap-1 text-emerald-400 sm:flex"><i className="h-2 w-2 rounded-full bg-emerald-400" />Prototype operational</span>
        <button className="relative text-slate-400" onClick={() => setTab('Incident Response')}><Bell size={18} />{st.open > 0 && <span className="absolute -right-2 -top-2 rounded-full bg-red-500 px-1 text-[10px] text-white">{st.open}</span>}</button>
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-cyan-500/20 font-semibold text-cyan-300">A</div></div>
    </header>
    <div className="flex min-h-0 flex-1 flex-col md:flex-row">
      <nav className={`flex shrink-0 gap-1 overflow-x-auto border-b border-slate-800 bg-slate-950/50 p-2 md:flex-col md:overflow-visible md:border-b-0 md:border-r ${col ? 'md:w-14' : 'md:w-56'}`}>
        {TABS.map(([n, I]) => <button key={n} title={n} onClick={() => setTab(n)} className={`flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm ${tab === n ? 'bg-cyan-500/10 text-cyan-300' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'}`}><I size={16} className="shrink-0" /><span className={col ? 'md:hidden' : ''}>{n}</span></button>)}
      </nav>
      <main className="min-w-0 flex-1 overflow-y-auto p-4"><h1 className="mb-4 text-lg font-semibold">{tab}</h1>
        {tab === 'Overview' && <Overview ev={ev} st={st} goto={goto} />}
        {tab === 'Honeytoken Vault' && <Vault S={S} ev={ev} notify={notify} load={load} />}
        {tab === 'Threat Events' && <Events ev={ev} setSel={setSel} />}
        {tab === 'Risk Analysis' && <Risk ev={ev} S={S} />}
        {tab === 'Webhook Inspector' && <Hooks S={S} notify={notify} load={load} />}
        {tab === 'Incident Response' && <Incidents ev={ev} act={act} pick={pick} setPick={setPick} />}
        {tab === 'Settings' && <Settings S={S} notify={notify} load={load} />}
      </main>
    </div>
    {drawer && <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={() => setSel(null)}><aside className="h-full w-full overflow-y-auto border-l border-slate-800 bg-slate-950 p-4 sm:w-[480px]" onClick={e => e.stopPropagation()}><div className="mb-3 flex items-center justify-between"><h2 className="text-sm font-semibold">Event details</h2><button onClick={() => setSel(null)}><X size={18} /></button></div><Detail e={drawer} onAct={act} /></aside></div>}
    {toast && <div className={`fixed bottom-4 right-4 z-50 max-w-sm rounded-lg border p-3 text-xs shadow-lg ${toast.ok ? 'border-emerald-500/40 bg-slate-900 text-emerald-300' : 'border-red-500/40 bg-slate-900 text-red-300'}`}>{toast.msg}{toast.goto && <button className="ml-2 underline" onClick={() => goto(toast.goto)}>View event</button>}</div>}
  </div>;
}
