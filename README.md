# Creluna Cyber · The Vault Challenge

Creluna Cyber is a defensive-security laboratory built around an isolated
challenge server called **THE VAULT** (`TV-01`). The public command center shows
only sanitized, delayed security data. It never receives raw payloads, secrets,
or direct access to defensive controls.

## What this version contains

- an interactive live command center;
- a clearly identified isolated challenge server;
- five explainable defensive agents;
- deterministic policy enforcement;
- a safe scenario runner for authorized laboratory events;
- persistent security events and audit records through Cloudflare D1;
- a sanitized dashboard API;
- automated policy and rendering tests.

The current release is a laboratory foundation. It does not scan, attack, or
modify external systems. High-impact actions are proposals only and require a
human decision.

## Defensive agents

| Agent | Responsibility |
| --- | --- |
| AEGIS | Correlates signals and cites evidence. |
| ARGINE | Proposes scoped, reversible containment. |
| ORBIT | Protects identities and demo sessions. |
| DECOY | Routes approved sessions to an internal decoy. |
| PHOENIX | Verifies recovery plans and clean snapshots. |

## Safety boundary

The agent council can propose only typed actions from an allowlist. A separate
Policy Guard checks the authorized asset, evidence count, confidence, action
impact, and approval state. There is no shell access, arbitrary code execution,
external network targeting, or offensive counterattack capability.

## Development

The application uses React, vinext, Cloudflare Workers, D1, Drizzle, and Node's
built-in test runner. Use the package scripts for local development, builds,
schema generation, and tests.
