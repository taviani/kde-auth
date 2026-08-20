CREATE TABLE registration_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX registration_tickets_token_hash_idx
    ON registration_tickets (token_hash);

CREATE INDEX registration_tickets_expires_at_idx
    ON registration_tickets (expires_at);
