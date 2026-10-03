CREATE TABLE network_documents (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('domain','certificate','endpoint','forwarding','tuning','tunnel','mesh','firewall')),
    revision BIGINT NOT NULL DEFAULT 1,
    config JSONB NOT NULL,
    active_version UUID,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX network_documents_kind ON network_documents(kind,updated_at DESC);
CREATE UNIQUE INDEX network_domain_name ON network_documents((config->>'name')) WHERE kind='domain';
CREATE UNIQUE INDEX network_managed_listener ON network_documents((config->>'server_id'),(config->>'listen_address'),(config->>'listen_port'),(config->>'protocol')) WHERE kind='forwarding' AND config->>'owner'='sinan' AND config->>'enabled'='true';

CREATE TABLE network_document_history (
    id UUID PRIMARY KEY,
    document_id UUID NOT NULL,
    kind TEXT NOT NULL,
    revision BIGINT NOT NULL,
    config JSONB NOT NULL,
    action TEXT NOT NULL,
    occurred_at BIGINT NOT NULL
);
CREATE INDEX network_document_history_latest ON network_document_history(document_id,occurred_at DESC);

CREATE TABLE network_certificate_versions (
    id UUID PRIMARY KEY,
    certificate_id UUID NOT NULL REFERENCES network_documents(id),
    revision BIGINT NOT NULL,
    public_chain TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    not_before BIGINT NOT NULL,
    not_after BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE(certificate_id,revision)
);

CREATE TABLE network_observations (
    id UUID PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES network_documents(id),
    server_id BIGINT REFERENCES servers(id),
    source TEXT NOT NULL,
    result JSONB NOT NULL,
    observed_at BIGINT NOT NULL
);
CREATE INDEX network_observations_latest ON network_observations(document_id,observed_at DESC);

CREATE TABLE network_operation_links (
    operation_id UUID PRIMARY KEY,
    document_id UUID REFERENCES network_documents(id),
    revision BIGINT,
    server_id BIGINT NOT NULL REFERENCES servers(id),
    request JSONB NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX network_operation_links_document ON network_operation_links(document_id,created_at DESC);

CREATE TABLE network_dns_challenges (
    id UUID PRIMARY KEY,
    certificate_id UUID NOT NULL REFERENCES network_documents(id),
    ddns_rule_id UUID NOT NULL,
    credential_id UUID,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    record_id TEXT,
    status TEXT NOT NULL,
    error_code TEXT,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE ddns_history (
    id UUID PRIMARY KEY,
    rule_id UUID NOT NULL,
    server_id BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    operation TEXT NOT NULL,
    desired_ip TEXT,
    previous JSONB,
    observed JSONB,
    status TEXT NOT NULL,
    error_code TEXT,
    occurred_at BIGINT NOT NULL
);
CREATE INDEX ddns_history_latest ON ddns_history(rule_id,occurred_at DESC);

CREATE TABLE ddns_migration_previews (
    id UUID PRIMARY KEY,
    target_server_id BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    applied_at BIGINT
);

CREATE TABLE network_acme_plans (
    certificate_id UUID PRIMARY KEY REFERENCES network_documents(id),
    config JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    account_secret_ref UUID,
    next_run_at BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    updated_at BIGINT NOT NULL
);
CREATE TABLE network_acme_jobs (
    id UUID PRIMARY KEY,
    certificate_id UUID NOT NULL REFERENCES network_documents(id),
    plan_revision BIGINT NOT NULL,
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    certificate_revision BIGINT NOT NULL,
    domain_snapshot JSONB NOT NULL,
    request JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    started_at BIGINT,
    completed_at BIGINT,
    result JSONB,
    key_secret_ref UUID,
    version_id UUID
);
CREATE UNIQUE INDEX network_acme_single_active ON network_acme_jobs(certificate_id) WHERE status IN ('queued','running','unknown');

CREATE TABLE dns_accounts (
    id UUID PRIMARY KEY,config JSONB NOT NULL,revision BIGINT NOT NULL DEFAULT 1,
    checked_at BIGINT,error_code TEXT,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL
);
CREATE TABLE dns_record_previews (
    id UUID PRIMARY KEY,account_id UUID NOT NULL,account_revision BIGINT NOT NULL,
    request JSONB NOT NULL,snapshot JSONB NOT NULL,created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,applied_at BIGINT
);
CREATE TABLE dns_record_history (
    id UUID PRIMARY KEY,account_id UUID NOT NULL,account_revision BIGINT NOT NULL,
    request JSONB NOT NULL,previous JSONB,observed JSONB,status TEXT NOT NULL,
    error_code TEXT,occurred_at BIGINT NOT NULL
);
CREATE INDEX dns_record_history_account ON dns_record_history(account_id,occurred_at DESC);

CREATE TABLE dns_resolver_observations (
    id UUID PRIMARY KEY,account_id UUID NOT NULL,request JSONB NOT NULL,
    result JSONB NOT NULL,occurred_at BIGINT NOT NULL
);
CREATE INDEX dns_resolver_observations_account ON dns_resolver_observations(account_id,occurred_at DESC);

CREATE TABLE network_certificate_deployment_previews (
    id UUID PRIMARY KEY,certificate_id UUID NOT NULL REFERENCES network_documents(id),
    certificate_revision BIGINT NOT NULL,version_id UUID NOT NULL REFERENCES network_certificate_versions(id),
    key_secret_ref UUID NOT NULL,snapshot JSONB NOT NULL,adopt_existing BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,applied_at BIGINT
);
CREATE TABLE network_certificate_deployments (
    id UUID PRIMARY KEY,certificate_id UUID NOT NULL REFERENCES network_documents(id),
    certificate_revision BIGINT NOT NULL,version_id UUID NOT NULL REFERENCES network_certificate_versions(id),
    key_secret_ref UUID NOT NULL,server_id BIGINT NOT NULL REFERENCES servers(id),
    target JSONB NOT NULL,adopt_existing BOOLEAN NOT NULL,requested_by BIGINT NOT NULL REFERENCES admins(id),
    operation_id UUID,status TEXT NOT NULL,created_at BIGINT NOT NULL
);
CREATE INDEX network_certificate_deployments_latest ON network_certificate_deployments(certificate_id,created_at DESC);
