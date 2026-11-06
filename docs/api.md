# AgentShield HTTP API

The live OpenAPI schema and interactive reference are served from `/openapi.json` and `/docs`.

All action and reviewer endpoints use `Authorization: Bearer <JWT>`. Tokens are short-lived and the service looks up the current active account and role for each request.

## Login

`POST /auth/login`

```json
{"username":"<account>","password":"<password>"}
```

Returns `access_token`, `token_type`, `username`, and `role`. Requests are rate-limited per network peer. Do not send credentials over plain HTTP outside local development.
Invalid accounts return `401`. If PostgreSQL is unavailable or rejects the configured database credentials, authentication returns `503` without disclosing connection details.

## Action gateway

`POST /check-action` — active agent account only.

```json
{
  "agent": "customer_support_bot",
  "user": "customer_support_bot",
  "tool": "customer.lookup",
  "action": "read",
  "resource": "customer",
  "environment": "development",
  "records": 1
}
```

The authenticated agent identity replaces the submitted `user` value and must match the registered agent. Policy evaluation is deny-by-default. Responses have a `decision` (`ALLOW`, `BLOCK`, `HUMAN_APPROVAL`, or `SANDBOX`), a reason, and—when applicable—approval id, execution status, and audit event. Tool and sandbox dispatch re-check their deterministic policy.

`POST /agents/simulate` accepts `{"actions":[<ActionRequest>, ...]}` for up to 20 actions. Every action is routed through the same authenticated gateway; this endpoint does not provide direct tool access.

## Human review

- `GET /approvals` lists pending requests for reviewer/security-admin accounts.
- `GET /approvals/history` returns the latest completed approval decisions, including reviewer identity.
- `POST /approvals/decision` accepts `{"approval_id":1,"approved":true}`. A rejection must include a non-empty `rejection_reason` of up to 500 characters.

Only the first decision of a pending approval can proceed. Duplicate pending actions return the same approval id.

## Monitoring

- `GET /agents` returns registered agent state and latest activity (reviewer-only).
- `GET /audit-logs` returns the latest 100 structured audit rows (reviewer-only).
- `GET /security/summary` returns decision counts and recent anomaly observations (reviewer-only).
- `GET /security/policies` returns the active deny-by-default YAML policy rules (reviewer-only).
- `POST /security/benchmark` runs the isolated attack benchmark and returns computed metrics (reviewer/security-admin only). It uses synthetic SQLite data and mocked action executors.

Anomaly results may have no risk score until enough approved baseline events exist. They are observational data only and cannot allow or block a request.
