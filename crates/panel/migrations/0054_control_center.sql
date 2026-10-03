ALTER TABLE admins DROP CONSTRAINT admins_id_check;
CREATE SEQUENCE admin_identity_seq START 2;
ALTER TABLE admins ALTER COLUMN id SET DEFAULT nextval('admin_identity_seq');
CREATE TABLE administrator_profiles (
    admin_id BIGINT PRIMARY KEY REFERENCES admins(id),
    login_name TEXT NOT NULL UNIQUE CHECK (octet_length(login_name) BETWEEN 1 AND 100),
    display_name TEXT NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 200),
    role TEXT NOT NULL CHECK (role IN ('owner', 'operator', 'viewer')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    all_servers BOOLEAN NOT NULL DEFAULT FALSE,
    capabilities JSONB NOT NULL DEFAULT '[]',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,created_at,updated_at)
SELECT 1,'admin','所有者','owner',TRUE,0,0 FROM admins WHERE id=1;
CREATE TABLE administrator_server_grants (
    admin_id BIGINT NOT NULL REFERENCES admins(id),
    server_id BIGINT NOT NULL REFERENCES servers(id),
    PRIMARY KEY(admin_id,server_id)
);
CREATE TABLE administrator_reauth (
    session_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
    verified_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE TABLE management_api_tokens (
    id UUID PRIMARY KEY,
    admin_id BIGINT NOT NULL REFERENCES admins(id),
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    capabilities JSONB NOT NULL,
    server_ids JSONB NOT NULL,
    all_servers BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX management_api_tokens_expiry ON management_api_tokens(expires_at);
CREATE TABLE management_audit (
    id BIGSERIAL PRIMARY KEY,
    admin_id BIGINT REFERENCES admins(id),
    token_id UUID,
    action TEXT NOT NULL,
    object_path TEXT NOT NULL,
    request_diff JSONB NOT NULL,
    result JSONB NOT NULL,
    occurred_at BIGINT NOT NULL
);
CREATE INDEX management_audit_time ON management_audit(occurred_at);
CREATE TABLE credential_entries (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('dns','cloud','backup','external-api','certificate')),
    key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    rotated_at BIGINT
);
ALTER TABLE alicloud_accounts ADD CONSTRAINT alicloud_accounts_credential_fk
    FOREIGN KEY(credential_id) REFERENCES credential_entries(id);
ALTER TABLE operations_hetzner_accounts ADD CONSTRAINT operations_hetzner_credential_fk
    FOREIGN KEY(credential_id) REFERENCES credential_entries(id);
CREATE TABLE administrator_preferences (
    admin_id BIGINT NOT NULL REFERENCES admins(id),
    preference_key TEXT NOT NULL,
    value JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY(admin_id,preference_key)
);
CREATE TABLE record_retention_policy (
    kind TEXT PRIMARY KEY CHECK (kind IN ('monitoring','logs','ip','terminal','proxy-access','audit')),
    days INTEGER NOT NULL CHECK (days BETWEEN 1 AND 3650),
    updated_at BIGINT NOT NULL
);
INSERT INTO record_retention_policy(kind,days,updated_at) VALUES
('monitoring',90,0),('logs',30,0),('ip',30,0),('terminal',7,0),('proxy-access',30,0),('audit',365,0);
CREATE TABLE system_worker_heartbeats (
    name TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('running','healthy','failed')),
    observed_at BIGINT NOT NULL,
    last_success_at BIGINT,
    details JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE system_observer_reports (
    id BIGSERIAL PRIMARY KEY,
    observer_name TEXT NOT NULL,
    target_origin TEXT NOT NULL,
    observed_at BIGINT NOT NULL,
    received_at BIGINT NOT NULL,
    available BOOLEAN,
    elapsed_ms BIGINT,
    evidence JSONB NOT NULL
);
CREATE INDEX system_observer_received ON system_observer_reports(received_at);

CREATE TABLE tool_advisory_observations (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('lookup-error','no-recorded-advisory','advisories-incomplete','advisories-recorded')),
    checked_at BIGINT NOT NULL,
    observed_at BIGINT,
    evidence JSONB NOT NULL DEFAULT '{}',
    error TEXT,
    PRIMARY KEY(ecosystem,name,version)
);
