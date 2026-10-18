HoneyShield

Detect Early. Respond Intelligently. Protect Sensitive Data.

A honeytoken-based threat detection prototype built for the IBM Z Datathon. Challenge: AI Secured: Innovation Without Exposure.

The problem

Data breaches can stay undetected for months. Traditional IP-based blocking can disrupt legitimate users and still miss suspicious activity.

The solution

HoneyShield plants synthetic decoy files (honeytokens). Legitimate users have no reason to open them, so any access is a strong signal. Each access becomes a signed webhook event that the server verifies, scores with a transparent risk engine, and turns into an incident that an analyst can act on.

Features
Honeytoken Vault: five synthetic decoys with access counts, last-triggered times, and a Simulate Access button.
Signed webhooks: HMAC-SHA256 signing, timing-safe verification, timestamp window, and replay protection.
Explainable risk scoring: weighted signals (honeytoken, traffic, synthetic threat intel, repeated access) with the reasons shown for every score.
Incident response: acknowledge, investigate, resolve, simulated rate limit, and simulated IP block (with confirmation), all in a timestamped audit trail.
SOC-style dashboard: charts, filterable event table, detail panels, and a system health panel.
Configurable engine: weights, alert threshold, and timestamp window in Settings.
Tech stack

Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, Recharts, Lucide React, Node.js crypto.

Quick start

Requires Node.js 18.17 or newer.

bash
npm install
npm run dev

Open http://localhost:3000. The dashboard loads with synthetic data and no setup.

Optional: set a webhook signing secret.

bash
cp .env.example .env.local
# edit HONEYSHIELD_SECRET

If unset, a clearly labelled development-only fallback secret is used. Never reuse it outside local demos.

Demo walkthrough
Open Overview: populated charts and tables.
Honeytoken Vault → Simulate Access on payroll_backup.csv.
Click View event in the notification: see the risk score and reasons, and the verified webhook.
Webhook Inspector → Simulate Invalid Signature (rejected), then Generate Test Event and Simulate Duplicate Event (rejected by replay protection).
Incident Response → Acknowledge Alert, then Simulate Rate Limit. Check the audit trail and the Overview counts.
Project structure
app/
  page.tsx                    Dashboard UI (all seven pages)
  layout.tsx, globals.css
  api/
    state/                    GET   dashboard, events, tokens, webhook log
    tokens/[id]/access/       POST  simulate honeytoken access
    events/[id]/              GET   event details
    webhook/                  POST  generate | verify | invalid | duplicate
    incidents/[id]/           POST  acknowledge | investigate | resolve | ratelimit | block
    config/                   GET/PUT scoring configuration
    reset/                    POST  reset demo data
lib/store.ts                  In-memory store, scoring, webhook verification, incident logic
How the risk score works
risk = sum(weight_i x signal_i) / sum(weights) x 100     (clamped to 0-100)

Default weights: honeytoken 45, traffic 25, threat intel 15, repeated access 15. Severity: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical. Incidents are created when risk is at or above the alert threshold (default 60).

The engine is a deterministic function (score() in lib/store.ts), isolated so a trained model can replace it later.

What is real and what is simulated

Implemented (server-side)

HMAC-SHA256 signing and timing-safe verification
Timestamp-window checks and duplicate-event rejection
Weighted risk scoring and configurable weights
Incident state transitions with validation and audit entries

Simulated

Threat intelligence: a small hardcoded list of reserved documentation IPs, labelled SYNTHETIC
Anomaly scoring: deterministic weighted scoring, not a trained ML model
Rate limiting and IP blocking: audit entries only; no firewall or real traffic is touched
System health indicators describe this local prototype only
Limitations
Data is held in server memory and resets when the server restarts. This is not a production persistence layer.
No authentication or role-based access.
Alert severity preferences in Settings are interface-only.
Designed for desktop; mobile layout is basic.
Safety

All files, events, and records are synthetic. Only reserved documentation IP ranges are used (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, per RFC 5737). The app performs no external scanning, no real blocking, and no real data collection.

Open-source resources
Resource	Use	License
Next.js	Framework and API routes	MIT
React	UI	MIT
Recharts	Charts	MIT
Lucide	Icons	ISC
Tailwind CSS	Styling	MIT
PostCSS / Autoprefixer	CSS processing	MIT
TypeScript	Type checking	Apache-2.0
Node.js crypto	HMAC-SHA256	built in

No external datasets, APIs, or threat feeds are used.

Roadmap
Integrate a trained anomaly-detection model
Add a persistent database
Connect real threat-intelligence feeds
Add authentication and role-based access
