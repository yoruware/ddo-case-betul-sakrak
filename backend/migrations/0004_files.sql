-- +goose Up
CREATE TABLE blobs (
    sha256     TEXT PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE file_versions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id       UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    version_no    INT  NOT NULL CHECK (version_no >= 1),
    sha256        TEXT NOT NULL REFERENCES blobs(sha256),
    size_bytes    BIGINT NOT NULL,
    mime_type     TEXT NOT NULL,
    original_name TEXT NOT NULL,
    uploaded_by   UUID NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (node_id, version_no)
);
CREATE INDEX idx_file_versions_sha ON file_versions (sha256);

CREATE TABLE quarantine_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256        TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    original_name TEXT NOT NULL,
    reason        TEXT NOT NULL,
    parent_id     UUID REFERENCES nodes(id) ON DELETE SET NULL,
    uploaded_by   UUID NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE quarantine_items;
DROP TABLE file_versions;
DROP TABLE blobs;