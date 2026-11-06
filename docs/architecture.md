# AgentShield architecture

```text
Agent client / React console
          |
          v
FastAPI routes ---- JWT + live account role checks
          |
          v
Action gateway ---- YAML policy (ABAC match, default BLOCK)
     |       |                  |
     |       +--> Redis atomic sliding-window counter (fail closed)
     +----------> IsolationForest risk signal (never authorizes)
          |
          +--> PostgreSQL approvals/audit
          |
          +--> allow-listed simulated tool executor
          |
          +--> internal sandbox API --> isolated Docker container
```

## Request path

1. Login rate-limits by network peer, verifies a bcrypt hash, then returns a short-lived HS256 token with issuer, audience, issued-at, expiry, and unique token id claims.
2. Each request resolves the token subject against the current active database account. Reviewer routes require a live reviewer/security-admin role; action routes require an active agent account matching the registered agent name.
3. The policy engine verifies the registered agent and account, then evaluates ordered YAML rules for agent, resource, action, environment, record ceiling, and policy decision. Unmatched operations block. ML has no authorization callback.
4. Configured limits are incremented atomically in Redis with a Lua script. Redis errors return 503 before action processing.
5. Approval decisions re-check policy and lock the approval row; a pending-only unique index and state transition prevent duplicate pending/replayed decisions. Real external tool execution is not implemented.
6. Every decision is persisted as an audit row, together with the optional anomaly score. Reviewer-only routes expose pending approvals, agent monitoring, and audit/summary views.

## Isolation boundary

The fixed `demo.preview` operation can be sent to a dedicated Docker sandbox service. Compose attaches it only to an internal network and applies read-only root filesystem, no capabilities, no-new-privileges, resource limits, and a non-root identity. The runner is allow-listed and does not execute user-provided code, shell commands, or arbitrary tool arguments. This boundary is real container isolation but is not a general-purpose sandbox and does not safely contain arbitrary programs.

## Persistence

SQLAlchemy models declare uniqueness/check constraints and indexes for new schemas. Existing PostgreSQL databases require the explicit migration script. Approval transitions and audit insertion are currently separate transactions; production integrations should add a transactional outbox and audited recovery for `EXECUTING` jobs.
