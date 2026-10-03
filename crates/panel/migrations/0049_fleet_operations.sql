CREATE TABLE fleet_templates (
 id UUID PRIMARY KEY, name TEXT NOT NULL, config JSONB NOT NULL,
 created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE TABLE fleet_profiles (
 server_id BIGINT PRIMARY KEY REFERENCES servers(id),
 asset JSONB NOT NULL DEFAULT '{}'::jsonb,
 policy JSONB NOT NULL DEFAULT '{}'::jsonb,
 lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','maintenance','draining','retired')),
 maintenance_from BIGINT, maintenance_until BIGINT,
 maintenance_reason TEXT NOT NULL DEFAULT '',
 updated_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE fleet_cost_records (
 id UUID PRIMARY KEY, server_id BIGINT NOT NULL REFERENCES servers(id),
 kind TEXT NOT NULL CHECK (kind IN ('purchase','renewal','price_change','refund','cancellation')),
 amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0), currency TEXT NOT NULL,
 occurred_at BIGINT NOT NULL, valid_until BIGINT, reference TEXT NOT NULL,
 created_at BIGINT NOT NULL
);
CREATE TABLE fleet_events (
 id UUID PRIMARY KEY, server_id BIGINT REFERENCES servers(id),
 kind TEXT NOT NULL, source TEXT NOT NULL, occurred_at BIGINT NOT NULL, detail JSONB NOT NULL
);
CREATE INDEX fleet_events_server_idx ON fleet_events(server_id,occurred_at DESC);
CREATE TABLE fleet_operations (
 id UUID PRIMARY KEY, server_id BIGINT NOT NULL REFERENCES servers(id),
 operation JSONB NOT NULL, policy JSONB NOT NULL, requested_by BIGINT REFERENCES admins(id), automation_job_id UUID, requested_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','expired','unknown','cancelled')),
 dispatched_at BIGINT, result JSONB, result_digest TEXT,
 reconciliation_of UUID REFERENCES fleet_operations(id) ON DELETE SET NULL, reconciled_at BIGINT, reconciliation JSONB
);
CREATE INDEX fleet_operations_pending_idx ON fleet_operations(server_id,requested_at) WHERE status='queued';
CREATE TABLE fleet_terminal_sessions (
 id UUID PRIMARY KEY, server_id BIGINT NOT NULL REFERENCES servers(id), admin_id BIGINT NOT NULL,
 account TEXT NOT NULL, admin_session_hash TEXT NOT NULL, policy JSONB NOT NULL, columns INTEGER NOT NULL, rows INTEGER NOT NULL,
 created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, last_input_at BIGINT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued', close_requested BOOLEAN NOT NULL DEFAULT FALSE,
 input_sequence BIGINT NOT NULL DEFAULT 0, output_sequence BIGINT NOT NULL DEFAULT 0,
 output_bytes BIGINT NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE fleet_terminal_inputs (
 session_id UUID NOT NULL REFERENCES fleet_terminal_sessions(id), sequence BIGINT NOT NULL,
 data TEXT NOT NULL, columns INTEGER, rows INTEGER, PRIMARY KEY(session_id,sequence)
);
CREATE TABLE fleet_terminal_outputs (
 session_id UUID NOT NULL REFERENCES fleet_terminal_sessions(id), sequence BIGINT NOT NULL,
 data TEXT NOT NULL, digest TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY(session_id,sequence)
);
CREATE TABLE fleet_config_history (
 id UUID PRIMARY KEY, server_id BIGINT NOT NULL REFERENCES servers(id), path TEXT NOT NULL,
 operation_id UUID NOT NULL UNIQUE REFERENCES fleet_operations(id), previous_sha256 TEXT NOT NULL,
 sha256 TEXT NOT NULL, content TEXT NOT NULL, created_at BIGINT NOT NULL
);
