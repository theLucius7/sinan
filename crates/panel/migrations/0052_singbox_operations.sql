-- Reviewable plugin-owned operations preserve original device and usage identities.
CREATE TABLE singbox_operation_previews (
    id UUID PRIMARY KEY,
    administrator_id BIGINT NOT NULL,
    request JSONB NOT NULL,
    fingerprint TEXT NOT NULL,
    summary JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    receipt JSONB
);
CREATE INDEX singbox_operation_previews_expiry ON singbox_operation_previews(expires_at);

CREATE TABLE singbox_operation_events (
    id BIGSERIAL PRIMARY KEY,
    administrator_id BIGINT,
    user_id BIGINT REFERENCES users(id),
    action TEXT NOT NULL,
    detail JSONB NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX singbox_operation_events_user ON singbox_operation_events(user_id, created_at DESC);
CREATE TABLE singbox_operation_privacy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    administrator_days INTEGER NOT NULL DEFAULT 180 CHECK(administrator_days BETWEEN 1 AND 3650),
    subscription_days INTEGER NOT NULL DEFAULT 7 CHECK(subscription_days BETWEEN 0 AND 365),
    security_days INTEGER NOT NULL DEFAULT 90 CHECK(security_days BETWEEN 1 AND 3650)
);
INSERT INTO singbox_operation_privacy(singleton) VALUES(TRUE);

CREATE TABLE singbox_quota_credits (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    cycle_start BIGINT NOT NULL,
    next_reset BIGINT NOT NULL CHECK(next_reset > cycle_start),
    bytes NUMERIC(30,0) NOT NULL CHECK(bytes >= 0),
    created_at BIGINT NOT NULL,
    administrator_id BIGINT NOT NULL
);
CREATE INDEX singbox_quota_credits_cycle ON singbox_quota_credits(user_id, cycle_start, next_reset);

ALTER TABLE usage_batches ADD COLUMN received_at BIGINT;
ALTER TABLE usage_batches ADD COLUMN last_replayed_at BIGINT;
ALTER TABLE usage_batches ADD COLUMN replay_count BIGINT NOT NULL DEFAULT 0 CHECK(replay_count >= 0);

-- A manual reset adds an explicit credit. Late usage still charges the ledger,
-- replay protection and runtime epochs remain unchanged.
CREATE OR REPLACE FUNCTION singbox_entitlements(at_s BIGINT)
RETURNS TABLE (user_id BIGINT, package_group_id BIGINT, package_name TEXT, monthly_bytes TEXT,
    reset_day INTEGER, reset_hour INTEGER, reset_minute INTEGER, timezone TEXT,
    starts_at BIGINT, expires_at BIGINT, cycle_start BIGINT, next_reset BIGINT,
    used_bytes TEXT, status TEXT, allowed BOOLEAN)
LANGUAGE sql STABLE AS $$
    WITH evaluated AS (
        SELECT u.id, a.package_group_id, a.package_name, a.monthly_bytes,
            a.reset_day, a.reset_hour, a.reset_minute, a.timezone, a.starts_at, a.expires_at,
            b.cycle_start, b.next_reset, GREATEST(COALESCE(t.used,0)-COALESCE(c.credit,0),0) AS used,
            CASE WHEN a.id IS NULL THEN 'unmetered'
                WHEN at_s < a.starts_at THEN 'not_started'
                WHEN at_s >= a.expires_at THEN 'expired'
                WHEN a.monthly_bytes IS NOT NULL AND GREATEST(COALESCE(t.used,0)-COALESCE(c.credit,0),0) >= a.monthly_bytes THEN 'exhausted'
                ELSE 'active' END AS status
        FROM users u
        LEFT JOIN singbox_user_packages p ON p.user_id=u.id
        LEFT JOIN singbox_package_assignments a ON a.id=p.assignment_id
        LEFT JOIN LATERAL singbox_cycle_bounds(at_s,a.reset_day,a.reset_hour,a.reset_minute,a.timezone) b ON TRUE
        LEFT JOIN LATERAL (
            SELECT SUM(r.uplink+r.downlink) AS used FROM usage_records r
            WHERE r.user_id=u.id AND r.period_end>b.cycle_start AND r.period_end<=b.next_reset
        ) t ON TRUE
        LEFT JOIN LATERAL (
            SELECT SUM(q.bytes) AS credit FROM singbox_quota_credits q
            WHERE q.user_id=u.id AND q.cycle_start=b.cycle_start AND q.next_reset=b.next_reset
        ) c ON TRUE
        WHERE u.deleted_at IS NULL
    )
    SELECT id,package_group_id,package_name,monthly_bytes::TEXT,reset_day,reset_hour,reset_minute,timezone,
        starts_at,expires_at,cycle_start,next_reset,used::TEXT,status,status IN('unmetered','active') FROM evaluated;
$$;

CREATE TABLE singbox_client_templates (
    user_id BIGINT PRIMARY KEY REFERENCES users(id),
    revision BIGINT NOT NULL DEFAULT 1 CHECK(revision > 0),
    client TEXT NOT NULL CHECK(client='singbox'),
    client_version TEXT NOT NULL CHECK(client_version='1.14.2'),
    definition JSONB NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE singbox_credential_rotations (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    server_id BIGINT NOT NULL REFERENCES servers(id),
    baseline_revision BIGINT NOT NULL,
    node_ids BIGINT[] NOT NULL,
    credential_fingerprint TEXT NOT NULL,
    requested_at BIGINT NOT NULL,
    confirmed_at BIGINT,
    confirmed_revision BIGINT
);

CREATE TABLE singbox_runtime_rollouts (
    id UUID PRIMARY KEY,
    administrator_id BIGINT NOT NULL,
    runtime_version TEXT NOT NULL CHECK(runtime_version='1.14.2'),
    targets BIGINT[] NOT NULL,
    batch_size INTEGER NOT NULL CHECK(batch_size BETWEEN 1 AND 20),
    dispatched_count INTEGER NOT NULL DEFAULT 0 CHECK(dispatched_count >= 0),
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    artifact_snapshot JSONB NOT NULL,
    completed_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE singbox_runtime_rollout_members (
    rollout_id UUID NOT NULL REFERENCES singbox_runtime_rollouts(id),
    server_id BIGINT NOT NULL REFERENCES servers(id),
    baseline_revision BIGINT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    inspect_request_id UUID NOT NULL,
    inspection_result JSONB,
    dispatched_at BIGINT NOT NULL,
    PRIMARY KEY(rollout_id,server_id)
);
