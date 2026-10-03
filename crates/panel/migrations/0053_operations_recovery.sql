ALTER TABLE alicloud_accounts ADD COLUMN credential_id UUID;

CREATE TABLE operations_templates (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    steps JSONB NOT NULL,
    created_by BIGINT NOT NULL REFERENCES admins(id),
    created_at BIGINT NOT NULL,
    archived BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE operations_jobs (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    template_id UUID REFERENCES operations_templates(id),
    spec JSONB NOT NULL,
    targets BIGINT[] NOT NULL CHECK(cardinality(targets) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK(status IN ('preview','queued','running','paused','cancel_requested','succeeded','failed','cancelled','uncertain')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    preview_digest TEXT NOT NULL,
    failure_reason TEXT,
    cancel_requested_at BIGINT,
    approved_batch INTEGER NOT NULL DEFAULT 0,
    source_schedule UUID,
    source_window BIGINT,
    UNIQUE(source_schedule,source_window)
);
CREATE TABLE operations_target_steps (
    job_id UUID NOT NULL REFERENCES operations_jobs(id),
    server_id BIGINT NOT NULL REFERENCES servers(id),
    position INTEGER NOT NULL,
    batch INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','queued','running','succeeded','failed','cancel_requested','cancelled','skipped','uncertain')),
    fleet_operation_id UUID UNIQUE REFERENCES fleet_operations(id),
    started_at BIGINT,
    finished_at BIGINT,
    result JSONB,
    PRIMARY KEY(job_id,server_id,position)
);
CREATE TABLE operations_server_locks (
    server_id BIGINT PRIMARY KEY REFERENCES servers(id),
    job_id UUID NOT NULL REFERENCES operations_jobs(id),
    acquired_at BIGINT NOT NULL
);
CREATE TABLE operations_history (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES operations_jobs(id),
    actor BIGINT REFERENCES admins(id),
    action TEXT NOT NULL,
    details JSONB NOT NULL,
    recorded_at BIGINT NOT NULL
);
CREATE TABLE operations_schedules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    spec JSONB NOT NULL,
    targets BIGINT[] NOT NULL CHECK(cardinality(targets) BETWEEN 1 AND 256),
    next_run_at BIGINT NOT NULL,
    interval_secs BIGINT NOT NULL CHECK(interval_secs BETWEEN 300 AND 31536000),
    timezone_offset_minutes INTEGER NOT NULL CHECK(timezone_offset_minutes BETWEEN -720 AND 840),
    missed_policy TEXT NOT NULL CHECK(missed_policy IN ('skip','run_once')),
    max_runs INTEGER NOT NULL CHECK(max_runs BETWEEN 1 AND 10000),
    run_count INTEGER NOT NULL DEFAULT 0,
    paused BOOLEAN NOT NULL DEFAULT true,
    last_job UUID REFERENCES operations_jobs(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE operations_remediation_rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    source_key TEXT NOT NULL,
    plan JSONB NOT NULL,
    targets BIGINT[] NOT NULL,
    cooldown_secs BIGINT NOT NULL CHECK(cooldown_secs BETWEEN 300 AND 604800),
    max_runs INTEGER NOT NULL CHECK(max_runs BETWEEN 1 AND 100),
    run_count INTEGER NOT NULL DEFAULT 0,
    paused BOOLEAN NOT NULL DEFAULT false,
    last_run_at BIGINT,
    last_job UUID REFERENCES operations_jobs(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE operations_backup_schedules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    interval_secs BIGINT NOT NULL CHECK(interval_secs BETWEEN 3600 AND 31536000),
    next_run_at BIGINT NOT NULL,
    paused BOOLEAN NOT NULL DEFAULT false,
    recipient TEXT NOT NULL,
    retention_count INTEGER NOT NULL CHECK(retention_count BETWEEN 1 AND 1000),
    retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 3650),
    last_started_at BIGINT,
    last_finished_at BIGINT,
    last_error TEXT,
    claimed_id UUID,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
ALTER TABLE operations_jobs ADD CONSTRAINT operations_job_schedule_fk FOREIGN KEY(source_schedule) REFERENCES operations_schedules(id);
CREATE TABLE operations_maintenance (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    targets BIGINT[] NOT NULL CHECK(cardinality(targets) BETWEEN 1 AND 256),
    starts_at BIGINT NOT NULL,
    ends_at BIGINT NOT NULL CHECK(ends_at>starts_at),
    suppress_notifications BOOLEAN NOT NULL DEFAULT true,
    block_new_tasks BOOLEAN NOT NULL DEFAULT true,
    created_by BIGINT NOT NULL REFERENCES admins(id),
    created_at BIGINT NOT NULL
);
CREATE INDEX operations_maintenance_window ON operations_maintenance(starts_at,ends_at);
CREATE TABLE operations_incidents (
    id UUID PRIMARY KEY,
    source_key TEXT NOT NULL,
    server_id BIGINT REFERENCES servers(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
    status TEXT NOT NULL CHECK(status IN ('open','acknowledged','resolved')),
    opened_at BIGINT NOT NULL,
    observed_at BIGINT NOT NULL,
    acknowledged_at BIGINT,
    acknowledged_by BIGINT REFERENCES admins(id),
    assignee BIGINT REFERENCES admins(id),
    escalation_after_secs INTEGER NOT NULL DEFAULT 3600 CHECK(escalation_after_secs BETWEEN 60 AND 604800),
    escalated_at BIGINT,
    resolved_at BIGINT,
    evidence JSONB NOT NULL,
    recovery_evidence JSONB,
    conclusion TEXT,
    notification_event BIGINT REFERENCES server_alert_events(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX operations_incident_active ON operations_incidents(source_key) WHERE status<>'resolved';
CREATE TABLE operations_incident_notes (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES operations_incidents(id),
    actor BIGINT REFERENCES admins(id),
    kind TEXT NOT NULL,
    note TEXT NOT NULL,
    evidence JSONB NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE TABLE operations_incident_deliveries (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES operations_incidents(id),
    channel TEXT NOT NULL CHECK(channel IN ('telegram','webhook')),
    kind TEXT NOT NULL CHECK(kind IN ('alert','escalation','recovery')),
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','sent','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL,
    last_error TEXT,
    delivered_at BIGINT,
    UNIQUE(incident_id,channel,kind)
);
CREATE TABLE operations_backup_records (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    manifest JSONB NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    storage_sha256 TEXT,
    location TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    verification TEXT NOT NULL CHECK(verification IN ('declared','integrity_verified','restored')),
    created_at BIGINT NOT NULL,
    imported_at BIGINT NOT NULL,
    imported_by BIGINT NOT NULL REFERENCES admins(id),
    source_schedule UUID REFERENCES operations_backup_schedules(id),
    retain_until BIGINT,
    dependency_ids UUID[] NOT NULL DEFAULT '{}',
    retired_at BIGINT
);
CREATE TABLE operations_restore_drills (
    id UUID PRIMARY KEY,
    backup_id UUID NOT NULL REFERENCES operations_backup_records(id),
    report JSONB NOT NULL,
    report_sha256 TEXT NOT NULL,
    passed BOOLEAN NOT NULL,
    recorded_at BIGINT NOT NULL,
    recorded_by BIGINT NOT NULL REFERENCES admins(id)
);
CREATE TABLE operations_cloud_links (
    resource_id UUID PRIMARY KEY REFERENCES alicloud_resources(id),
    server_id BIGINT REFERENCES servers(id),
    purchase_reference TEXT NOT NULL DEFAULT '',
    purchase_amount TEXT,
    currency TEXT,
    monthly_budget TEXT,
    expires_at BIGINT,
    notes TEXT NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL,
    updated_by BIGINT NOT NULL REFERENCES admins(id)
);
CREATE TABLE operations_cloud_observations (
    id BIGSERIAL PRIMARY KEY,
    resource_id UUID NOT NULL REFERENCES alicloud_resources(id),
    checked_at BIGINT NOT NULL,
    source TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    previous_snapshot JSONB,
    changes JSONB NOT NULL,
    UNIQUE(resource_id,checked_at,source)
);
CREATE INDEX operations_cloud_observation_history ON operations_cloud_observations(resource_id,checked_at DESC);

CREATE TABLE operations_cancellation_reminders (
    record_id UUID PRIMARY KEY REFERENCES fleet_cost_records(id),
    enabled BOOLEAN NOT NULL DEFAULT false,
    lead_secs BIGINT NOT NULL DEFAULT 604800 CHECK(lead_secs BETWEEN 3600 AND 2592000),
    configured_by BIGINT NOT NULL REFERENCES admins(id),
    configured_at BIGINT NOT NULL,
    notified_at BIGINT,
    incident_id UUID REFERENCES operations_incidents(id),
    last_error TEXT
);

CREATE TABLE operations_hetzner_accounts (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 800),
    credential_id UUID NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
    archived BOOLEAN NOT NULL DEFAULT false,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by BIGINT NOT NULL REFERENCES admins(id),
    last_attempt_at BIGINT,
    last_read_at BIGINT,
    last_error TEXT,
    refresh_id UUID,
    refresh_started_at BIGINT
);
CREATE TABLE operations_hetzner_resources (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES operations_hetzner_accounts(id),
    cloud_id TEXT NOT NULL,
    name TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    presence TEXT NOT NULL CHECK(presence IN ('observed','absent','unknown')),
    last_seen_at BIGINT,
    verified_at BIGINT,
    last_attempt_at BIGINT NOT NULL,
    error_code TEXT,
    server_id BIGINT REFERENCES servers(id),
    notes TEXT NOT NULL DEFAULT '',
    updated_at BIGINT NOT NULL,
    updated_by BIGINT REFERENCES admins(id),
    UNIQUE(account_id,cloud_id)
);
CREATE INDEX operations_hetzner_resource_scope ON operations_hetzner_resources(server_id,account_id);
CREATE TABLE operations_hetzner_refreshes (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES operations_hetzner_accounts(id),
    started_at BIGINT NOT NULL,
    completed_at BIGINT NOT NULL,
    complete BOOLEAN NOT NULL,
    pages INTEGER NOT NULL CHECK(pages BETWEEN 0 AND 10),
    observed INTEGER NOT NULL CHECK(observed BETWEEN 0 AND 500),
    error_code TEXT,
    CHECK(complete=(error_code IS NULL))
);
CREATE TABLE operations_hetzner_observations (
    id BIGSERIAL PRIMARY KEY,
    resource_id UUID NOT NULL REFERENCES operations_hetzner_resources(id),
    refresh_id UUID NOT NULL REFERENCES operations_hetzner_refreshes(id),
    observed_at BIGINT NOT NULL,
    source TEXT NOT NULL CHECK(source='hetzner_cloud_v1_servers'),
    presence TEXT NOT NULL CHECK(presence IN ('observed','absent','unknown')),
    snapshot JSONB NOT NULL,
    changes JSONB NOT NULL,
    UNIQUE(resource_id,refresh_id)
);
CREATE INDEX operations_hetzner_observation_history ON operations_hetzner_observations(resource_id,observed_at DESC);

ALTER TABLE runtime_operations ADD COLUMN automation_job_id UUID REFERENCES operations_jobs(id);
ALTER TABLE runtime_operations ADD COLUMN cancelled_at BIGINT;
ALTER TABLE runtime_operations ADD COLUMN reconciled_at BIGINT;
ALTER TABLE runtime_operations ADD COLUMN reconciliation JSONB;
ALTER TABLE runtime_operations ADD CONSTRAINT runtime_operations_reconciliation CHECK((reconciled_at IS NULL)=(reconciliation IS NULL));
ALTER TABLE runtime_operations ADD CONSTRAINT runtime_operations_local_cancel CHECK(cancelled_at IS NULL OR dispatched_at IS NULL);
DROP INDEX runtime_operations_one_active;
CREATE UNIQUE INDEX runtime_operations_one_active ON runtime_operations(server_id,module) WHERE result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL;

ALTER TABLE operations_target_steps ADD COLUMN runtime_operation_id UUID UNIQUE REFERENCES runtime_operations(id);
CREATE TABLE operations_panel_steps (
    job_id UUID NOT NULL REFERENCES operations_jobs(id),
    position INTEGER NOT NULL CHECK(position=0),
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','queued','running','succeeded','failed','cancelled','uncertain')),
    execution_id UUID NOT NULL UNIQUE,
    backup_id UUID REFERENCES operations_backup_records(id),
    spec JSONB NOT NULL,
    claimed_at BIGINT,
    finished_at BIGINT,
    result JSONB,
    PRIMARY KEY(job_id,position)
);
