-- Rollback: Remove status field from invitations
CREATE TABLE invitations_old (
  id TEXT PRIMARY KEY,
  organisation_id TEXT NOT NULL,
  email TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  role TEXT DEFAULT 'member',
  invited_by TEXT,
  expires_at DATETIME NOT NULL,
  accepted_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Copy data back without status
INSERT INTO invitations_old (id, organisation_id, email, token, role, invited_by, expires_at, accepted_at, created_at)
SELECT id, organisation_id, email, token, role, invited_by, expires_at, accepted_at, created_at
FROM invitations;

-- Drop new table
DROP TABLE invitations;

-- Rename old table
ALTER TABLE invitations_old RENAME TO invitations;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_organisation_id ON invitations(organisation_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
