# Kreluna Cyber · The Vault Challenge

Kreluna Cyber is a defensive-security laboratory built around an isolated
challenge server called **THE VAULT** (`TV-01`). The public command center shows
only sanitized laboratory security data. It never receives raw payloads, secrets,
or direct access to defensive controls.

## What V0.4 contains

- an interactive command center;
- a clearly identified isolated challenge server;
- five specialist defensive modules with separate typed assessments;
- explainable council consensus, quorum, risk, confidence, and dissent;
- versioned deterministic policy enforcement with an absolute safety veto;
- a safe scenario runner for authorized laboratory events;
- event-driven guarded autonomy for four reversible, state-only actions;
- a non-blocking post-action review log, with restore kept as a separate manual-only exception;
- persistent events, assessments, consensus, approvals, and audit records through
  Cloudflare D1;
- a sanitized dashboard API;
- automated policy and rendering tests.

The current release is a deterministic laboratory council with a provider
boundary for future advisory models. It is not presented as a connected LLM or
as a Cloudflare Agents SDK/Durable Object runtime. It does not scan, attack, or
modify external systems. Four allowlisted defenses can update laboratory state
autonomously after evidence, quorum, confidence, and policy checks. Snapshot
restore remains manual-only and still produces only an internal state change.

Event ingress is currently triggered through the authenticated laboratory API
by an operator running one of the four safe scenarios. This release does not yet
include live sensor ingestion, background monitoring, or a scheduler. The
autonomy is in the decision and bounded state-only response after a lab event is
received; connecting real-time defensive telemetry is a later phase.

## Defensive agents

| Agent | Responsibility |
| --- | --- |
| AEGIS | Correlates sanitized evidence and verifies the signal quorum. |
| ARGINE | Evaluates containment scope, reversibility, and policy preconditions. |
| ORBIT | Reviews identity/session risk and privilege boundaries. |
| DECOY | Evaluates isolated deception proposals without routing external traffic. |
| PHOENIX | Reviews recovery readiness, checkpoint integrity, and rollback safety. |

Each module produces a validated report with a vote, a bounded confidence score,
trust prior, evidence references, safeguards, and a concise rationale.
The council requires a valid five-report set and role-aware quorum before the
Policy Guard will consider a state-only simulation.

## Safety boundary

The council can recommend only typed actions from an allowlist. A separate Policy
Guard checks the authorized asset, evidence, quorum, confidence, action impact,
and policy version before guarded-autopilot state updates. Council or model output
cannot override the guard with a broader permission; a validated council may only
make the outcome more restrictive. There is no shell access, arbitrary code
execution, external network targeting, or offensive counterattack capability.

Post-action reviews do not pause the autopilot. Manual restore requests are
one-shot records tied to the original proposal. Approve and reject operations
update the laboratory state and audit trail; they do not execute network,
system, or offensive actions.

Every state-changing API request must be same-origin, use a bounded exact JSON
envelope, carry an idempotency key, and come from a platform-authenticated
private-site operator. Mutations require durable D1 memory; if that memory is
missing or unhealthy, the API returns a failure and the client keeps the last
verified snapshot instead of fabricating a local success.

## Development

The application uses React, vinext, Cloudflare Workers, D1, Drizzle, and Node's
built-in test runner. Use the package scripts for local development, builds,
schema generation, and tests.
