CREATE TABLE user_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('primary', 'secondary')),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX user_emails_email_idx ON user_emails (lower(email));
CREATE UNIQUE INDEX user_emails_one_primary_idx ON user_emails (user_id) WHERE role = 'primary';
CREATE UNIQUE INDEX user_emails_one_secondary_idx ON user_emails (user_id) WHERE role = 'secondary';
CREATE INDEX user_emails_user_id_idx ON user_emails (user_id);

INSERT INTO user_emails (user_id, email, role, verified_at, created_at, updated_at)
SELECT id, email, 'primary', email_verified_at, created_at, updated_at
FROM users;

ALTER TABLE email_verification_tokens
    ADD COLUMN IF NOT EXISTS email TEXT;
