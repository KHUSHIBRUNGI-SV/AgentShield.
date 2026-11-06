-- Apply once to an existing PostgreSQL database before deploying this version.
-- Inspect and resolve duplicates before creating the unique indexes:
-- SELECT agent_id, resource, action, count(*) FROM permissions
--   GROUP BY agent_id, resource, action HAVING count(*) > 1;
-- SELECT permission_id, environment, count(*) FROM policies
--   GROUP BY permission_id, environment HAVING count(*) > 1;
-- SELECT agent, "user", tool, action, resource, environment, records, count(*)
--   FROM approval_requests WHERE status = 'PENDING'
--   GROUP BY agent, "user", tool, action, resource, environment, records
--   HAVING count(*) > 1;

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'user';
UPDATE users SET is_active = TRUE WHERE is_active IS NULL;
ALTER TABLE users ALTER COLUMN is_active SET NOT NULL;
UPDATE approval_requests SET records = 0 WHERE records IS NULL;
ALTER TABLE approval_requests ALTER COLUMN records SET NOT NULL;
UPDATE audit_logs SET records = 0 WHERE records IS NULL;
ALTER TABLE audit_logs ALTER COLUMN records SET NOT NULL;

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS anomaly_detected BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_permission_agent_resource_action
    ON permissions (agent_id, resource, action);
CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_permission_environment
    ON policies (permission_id, environment);
CREATE INDEX IF NOT EXISTS ix_approval_status_created
    ON approval_requests (status, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_approval_action
    ON approval_requests
       (agent, "user", tool, action, resource, environment, records)
    WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS ix_audit_timestamp
    ON audit_logs (timestamp);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_approval_nonnegative_records'
    ) THEN
        ALTER TABLE approval_requests
            ADD CONSTRAINT ck_approval_nonnegative_records
            CHECK (records >= 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_audit_nonnegative_records'
    ) THEN
        ALTER TABLE audit_logs
            ADD CONSTRAINT ck_audit_nonnegative_records
            CHECK (records >= 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_policy_nonnegative_max_records'
    ) THEN
        ALTER TABLE policies
            ADD CONSTRAINT ck_policy_nonnegative_max_records
            CHECK (max_records IS NULL OR max_records >= 0) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_policy_positive_rate_limit'
    ) THEN
        ALTER TABLE policies
            ADD CONSTRAINT ck_policy_positive_rate_limit
            CHECK (
                max_requests_per_minute IS NULL
                OR max_requests_per_minute > 0
            ) NOT VALID;
    END IF;
END $$;
