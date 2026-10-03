CREATE TABLE singbox_deployment_preflights (
    id UUID PRIMARY KEY,
    sequence BIGSERIAL NOT NULL UNIQUE,
    server_id BIGINT NOT NULL REFERENCES servers(id),
    administrator_id BIGINT NOT NULL REFERENCES admins(id),
    expected_digest TEXT NOT NULL CHECK(length(expected_digest)=64),
    snapshot JSONB NOT NULL,
    panel_checks JSONB NOT NULL,
    ports_operation_id UUID NOT NULL,
    permissions_operation_id UUID NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    confirmed_at BIGINT,
    confirmed_by BIGINT REFERENCES admins(id)
);
CREATE INDEX singbox_deployment_preflights_latest ON singbox_deployment_preflights(server_id,sequence DESC);
