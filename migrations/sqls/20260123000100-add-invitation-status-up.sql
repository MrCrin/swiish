-- SQLite doesn't support ALTER with FOREIGN KEY changes, must recreate table
CREATE TABLE invitations_new (
  id TEXT PRIMARY KEY,
  organisation_id TEXT NOT NULL,
  email TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  role TEXT DEFAULT 'member',
  invited_by TEXT,
  expires_at DATETIME NOT NULL,
  accepted_at DATETIME,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'sent', 'failed', 'accepted', 'expired')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Copy existing data with inferred status
INSERT INTO invitations_new (id, organisation_id, email, token, role, invited_by, expires_at, accepted_at, status, created_at)
SELECT
  id,
  organisation_id,
  email,
  token,
  role,
  invited_by,
  expires_at,
  accepted_at,
  CASE
    WHEN accepted_at IS NOT NULL THEN 'accepted'
    WHEN expires_at < datetime('now') THEN 'expired'
    ELSE 'sent'
  END as status,
  created_at
FROM invitations;

-- Drop old table
DROP TABLE invitations;

-- Rename new table
ALTER TABLE invitations_new RENAME TO invitations;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_organisation_id ON invitations(organisation_id);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON invitations(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
