-- Clean up orphaned data from pre-hard-delete era (soft delete remnants)

-- Clean up orphaned records in leaf tables first (tables that reference users)
DELETE FROM user_settings
WHERE user_id NOT IN (SELECT id FROM users);

DELETE FROM password_reset_tokens
WHERE user_id NOT IN (SELECT id FROM users);

DELETE FROM email_verification_tokens
WHERE user_id NOT IN (SELECT id FROM users);

-- Clean up orphaned cards
DELETE FROM cards
WHERE user_id NOT IN (SELECT id FROM users);

-- Clean up old soft-deleted users (organisation_id = NULL indicates old soft delete)
DELETE FROM users
WHERE organisation_id IS NULL;
