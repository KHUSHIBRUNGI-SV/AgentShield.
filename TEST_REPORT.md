# AgentShield Lifecycle Test Report

## Results

| Test tier | Total | Passed | Failed | Skipped / blocked |
|---|---:|---:|---:|---:|
| Backend pytest suite | 67 | 65 | 0 | 2 skipped |
| Dashboard Vitest components | 11 | 11 | 0 | 0 |
| Browser Playwright E2E | 1 | Not run | 0 assertions | 1 blocked before launch |

The backend suite completed in 26.95 seconds on this Windows environment.
The browser test runner could not launch because its Chromium executable is not
installed. An earlier browser download attempt failed with a Windows file-access
error. This is an environment limitation, not a passing browser test. The E2E
test is wired into GitHub Actions, where Chromium is installed as part of CI.

The isolated E2E server and Vite dashboard were separately started and probed:
the API docs and dashboard returned HTTP 200, and an authenticated agent action
returned `ALLOW` with an audit event ID. This is an HTTP smoke check, not a
substitute for the unrun browser assertions.

## Security scenarios exercised

- Agent registration, login, identity binding, suspension, and inactive-account
  rejection.
- Expired and missing JWT credentials, role-based reviewer access, and
  impersonation rejection.
- Deterministic `ALLOW` and `BLOCK` decisions, including a rate-limit denial
  that remains blocked and is audited.
- Human approval creation, authorized review, duplicate pending request
  handling, replay rejection, and concurrent reviewer decisions.
- Controlled executor invocation exactly once for a concurrent approval; the
  configured executor reports simulated/unavailable rather than performing a
  real external action.
- Persisted audit event readback, hash-chain integrity, and dashboard-facing
  summary data.
- Isolation Forest scoring after 20 observed benign events; a high-risk action
  remains `BLOCK` regardless of the advisory model score.
- CORS preflight for both `http://localhost:5173` and
  `http://127.0.0.1:5173`, including `PATCH`.
- Dashboard sign-in, API-shaped decision-to-theme updates, approval handling,
  audit view, and persisted preference component coverage using the existing
  Vitest suite.

Two live-service connectivity tests were skipped because dedicated PostgreSQL
and Redis test URLs were not configured. Existing unit tests cover database and
Redis error handling with controlled failures; live service recovery,
PostgreSQL-specific locking/migrations, and real Redis concurrency remain
unverified here.

## Benchmark

The repeatable controlled benchmark ran **160 scenarios** (100 attack, 60
legitimate) and **440 action requests** through the authenticated policy
gateway. It reported:

- Expected scenario outcomes met: 160/160; mismatches: 0.
- Attack request prevention: 47.37%; attack request success (ALLOW): 52.63%.
- Detection rate / recall: 44.74%; precision: 100%; F1: 61.82%.
- False-positive rate: 0%; legitimate action acceptance: 100%.
- Average decision latency: 7.3561 ms.

The attack-request success rate is materially affected by the controlled
rate-limit-abuse cases, where the configured policy intentionally allows up to
20 requests in a burst before blocking. These synthetic benchmark metrics are
not evidence of real-world protection and do not represent external agents,
live services, or real tools.

## Fixes and observations

- Replaced approval concurrency reliance on `SELECT ... FOR UPDATE` with a
  conditional state transition from `PENDING`; SQLite and concurrent-request
  tests confirmed only one reviewer wins and dispatches.
- Expanded CORS methods to include dashboard `PUT` and `PATCH` operations while
  preserving explicit-origin validation.
- Updated the persisted benchmark API test to assert the newly returned
  `run_id` and `started_at` metadata instead of rejecting those documented
  response fields.
- No additional exploitable issue was confirmed by the local lifecycle tests.

## Remaining limitations

- Browser-level assertions remain unverified locally until Chromium is
  available; CI is configured to run them.
- PostgreSQL, Redis, Docker Compose, and Docker sandbox runtime were not
  exercised in this environment. The lifecycle API tests use isolated SQLite,
  and Redis rate limiting is stubbed only in the E2E server.
- Tools are simulated and no production customer actions or external
  transactions were executed.

## Reproducible commands

From the project root:

```powershell
$env:PYTHONPATH = "backend"
.\.venv\Scripts\python.exe -m pytest -v
Set-Location dashboard
npm ci
npm test
npm run build
npx playwright install chromium
npm run test:e2e
Set-Location ..
.\.venv\Scripts\python.exe backend\benchmarks\run_benchmark.py
```

For live service tests, set `AGENTSHIELD_RUN_INTEGRATION_TESTS=1` and point
`AGENTSHIELD_TEST_DATABASE_URL` and `AGENTSHIELD_TEST_REDIS_URL` only at
dedicated disposable test services.
