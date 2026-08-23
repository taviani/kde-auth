ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS android_package TEXT NOT NULL DEFAULT '';
