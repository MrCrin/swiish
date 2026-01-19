-- Add performance indexes for frequently queried columns

-- Index on users.email for login lookups (most common query)
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Index on users.organisation_id for organization member queries
CREATE INDEX IF NOT EXISTS idx_users_organisation_id ON users(organisation_id);

-- Index on cards.user_id for fetching user's cards (N+1 query prevention)
CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id);

-- Index on cards.slug for card lookups by slug
CREATE INDEX IF NOT EXISTS idx_cards_slug ON cards(slug);

-- Index on invitations.email for invitation lookup
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);

-- Index on invitations.organisation_id for organization invitation queries
CREATE INDEX IF NOT EXISTS idx_invitations_organisation_id ON invitations(organisation_id);

-- Index on password_reset_tokens.token for password reset lookup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);

-- Index on email_verification_tokens.token for email verification lookup
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_token ON email_verification_tokens(token);
