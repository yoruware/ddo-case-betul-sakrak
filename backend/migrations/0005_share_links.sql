-- +goose Up
CREATE TABLE share_links (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id        UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash     TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    password_hash  TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    max_downloads  INT CHECK (max_downloads IS NULL OR max_downloads >= 1),
    download_count INT NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    revoked_at     TIMESTAMPTZ,
    created_by     UUID NOT NULL REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (max_downloads IS NULL OR download_count <= max_downloads)
);
CREATE INDEX idx_share_links_node ON share_links (node_id);

-- +goose Down
DROP TABLE share_links;