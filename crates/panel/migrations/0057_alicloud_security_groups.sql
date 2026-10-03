CREATE TABLE alicloud_security_group_operations (
    id UUID PRIMARY KEY,
    resource_id UUID NOT NULL REFERENCES alicloud_resources(id),
    requested_by BIGINT NOT NULL REFERENCES admins(id),
    before_state JSONB NOT NULL,
    target_groups TEXT[] NOT NULL CHECK(cardinality(target_groups) BETWEEN 1 AND 16),
    impact JSONB NOT NULL,
    snapshot_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('preview','running','unknown','succeeded','failed','reconciled')),
    steps JSONB NOT NULL DEFAULT '[]'::JSONB,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    observed_at BIGINT,
    actual_groups TEXT[],
    error_code TEXT,
    original_result TEXT,
    reconciliation JSONB
);
CREATE UNIQUE INDEX alicloud_security_group_active ON alicloud_security_group_operations(resource_id)
    WHERE status IN ('running','unknown');
CREATE INDEX alicloud_security_group_history ON alicloud_security_group_operations(resource_id,created_at DESC);
CREATE TABLE alicloud_managed_security_groups (
    resource_id UUID NOT NULL REFERENCES alicloud_resources(id),
    group_id TEXT NOT NULL,
    group_digest TEXT NOT NULL,
    operation_id UUID NOT NULL REFERENCES alicloud_security_group_operations(id),
    confirmed_at BIGINT NOT NULL,
    PRIMARY KEY(resource_id,group_id)
);
