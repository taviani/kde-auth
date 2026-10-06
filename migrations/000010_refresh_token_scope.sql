ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS scope TEXT;

UPDATE refresh_tokens
SET scope = 'openid email offline_access'
WHERE scope IS NULL OR scope = '';

ALTER TABLE refresh_tokens
    ALTER COLUMN scope SET NOT NULL;
