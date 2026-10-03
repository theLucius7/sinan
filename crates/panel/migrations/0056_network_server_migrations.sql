CREATE TABLE network_server_migration_previews (
    id UUID PRIMARY KEY,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    source_server_id BIGINT NOT NULL REFERENCES servers(id),
    target_server_id BIGINT NOT NULL REFERENCES servers(id),
    request JSONB NOT NULL,
    identity_map JSONB NOT NULL,
    snapshot JSONB NOT NULL,
    snapshot_digest TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    applied_at BIGINT,
    result JSONB
);
CREATE INDEX network_server_migration_latest
    ON network_server_migration_previews(source_server_id,created_at DESC);
