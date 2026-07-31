-- Public OAuth clients (mobile) + PKCE on authorization codes.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post';

-- Public clients may have an empty secret hash (no password to verify).
ALTER TABLE oauth_clients
    ALTER COLUMN client_secret_hash DROP NOT NULL;

ALTER TABLE oauth_clients
    ALTER COLUMN client_secret_hash SET DEFAULT '';

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS code_challenge TEXT,
    ADD COLUMN IF NOT EXISTS code_challenge_method TEXT;
