CREATE TABLE IF NOT EXISTS benchmark_runs (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor VARCHAR(128) NOT NULL,
    summary_json TEXT NOT NULL,
    scenarios_json TEXT NOT NULL,
    methodology_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_benchmark_started_at
    ON benchmark_runs (started_at);

CREATE TABLE IF NOT EXISTS policy_versions (
    id SERIAL PRIMARY KEY,
    version INTEGER NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    changed_by VARCHAR(128) NOT NULL,
    document_json TEXT NOT NULL,
    CONSTRAINT uq_policy_version UNIQUE (version)
);

CREATE TABLE IF NOT EXISTS user_preferences (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    preferences_json TEXT NOT NULL,
    CONSTRAINT uq_user_preference_user UNIQUE (user_id),
    CONSTRAINT fk_user_preferences_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
