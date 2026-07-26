ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'public';

CREATE TABLE invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    email TEXT NOT NULL,
    created_by UUID REFERENCES users (id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX invites_token_hash_idx ON invites (token_hash);
CREATE INDEX invites_client_id_idx ON invites (client_id);
CREATE INDEX invites_email_idx ON invites (lower(email));
