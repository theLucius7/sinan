CREATE TABLE network_workbench_targets (
 id uuid PRIMARY KEY, name text NOT NULL, host text NOT NULL, region text NOT NULL DEFAULT '',
 carrier text NOT NULL DEFAULT '', purpose text NOT NULL, authorization_snapshot text NOT NULL,
 authorized_until bigint, created_at bigint NOT NULL, updated_at bigint NOT NULL
);
CREATE TABLE network_workbench_plans (
 id uuid PRIMARY KEY, name text NOT NULL, definition jsonb NOT NULL, revision bigint NOT NULL DEFAULT 1,
 enabled boolean NOT NULL DEFAULT false, interval_secs bigint, next_run_at bigint,
 created_at bigint NOT NULL, updated_at bigint NOT NULL
);
CREATE TABLE network_workbench_runs (
 id uuid PRIMARY KEY, plan_id uuid REFERENCES network_workbench_plans(id), snapshot jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('queued','running','paused','cleaning','succeeded','failed','cancel_requested','cancelled')),
 current_step integer NOT NULL DEFAULT 0, actor text NOT NULL, error text, cancel_requested_at bigint,
 created_at bigint NOT NULL, updated_at bigint NOT NULL
);
CREATE TABLE network_workbench_results (
 id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES network_workbench_runs(id), step_index integer NOT NULL,
 server_id bigint REFERENCES servers(id), role text NOT NULL DEFAULT 'source', job_id uuid REFERENCES diagnostic_jobs(id),
 status text NOT NULL, result jsonb, created_at bigint NOT NULL, updated_at bigint NOT NULL,
 UNIQUE(run_id,step_index,role)
);
CREATE INDEX network_workbench_active_runs ON network_workbench_runs(status,created_at);
CREATE TABLE network_workbench_tools (
 id text PRIMARY KEY, version text NOT NULL, license text NOT NULL, source_url text NOT NULL,
 signature_required boolean NOT NULL DEFAULT true, licensed boolean NOT NULL DEFAULT false,
 platforms text[] NOT NULL DEFAULT '{}', updated_at bigint NOT NULL
);
CREATE TABLE network_workbench_providers (
 id uuid PRIMARY KEY, name text NOT NULL, endpoint text NOT NULL, credential_ref text,
 daily_quota integer NOT NULL DEFAULT 100, requests_today integer NOT NULL DEFAULT 0,
 quota_day bigint NOT NULL DEFAULT 0, cache_seconds integer NOT NULL DEFAULT 3600,
 disabled boolean NOT NULL DEFAULT false, updated_at bigint NOT NULL
);
CREATE TABLE network_workbench_ip_evidence (
 id uuid PRIMARY KEY, server_id bigint REFERENCES servers(id), address text NOT NULL, family text NOT NULL,
 source text NOT NULL, status text NOT NULL, evidence jsonb NOT NULL, observed_at bigint NOT NULL,
 expires_at bigint NOT NULL
);
CREATE TABLE network_workbench_shares (
 id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES network_workbench_runs(id), token_hash text NOT NULL UNIQUE,
 expires_at bigint NOT NULL, revoked_at bigint, redaction jsonb NOT NULL, created_at bigint NOT NULL
);
CREATE TABLE network_workbench_pairings (
 id uuid PRIMARY KEY, run_id uuid REFERENCES network_workbench_runs(id), token_hash text NOT NULL,
 expires_at bigint NOT NULL, used_at bigint, definition jsonb NOT NULL, created_at bigint NOT NULL
);
