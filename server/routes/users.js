const express = require('express');
const { body, param } = require('express-validator');
const bcrypt = require('bcrypt');
const { db } = require('../db');
const { apiLimiter, csrfProtection } = require('../config/security');
const { handleValidationErrors } = require('../middleware/validation');
const { requireAuth, requireRole } = require('../middleware/auth');
const { generateUuid } = require('../lib/tokens');
const { logAudit } = require('../lib/audit');

const router = express.Router();

// --- USER MANAGEMENT ENDPOINTS (Owners only) ---

// GET All Users in Organization
router.get('/api/admin/users', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all(
    "SELECT id, email, role, created_at FROM users WHERE organisation_id = ? ORDER BY created_at DESC",
    [req.user.organisationId],
    (err, rows) => {
      if (err) return next(err);
      res.json(rows);
    }
  );
});

// POST Create User (Manual creation by owner)
router.post('/api/admin/users', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('email').isEmail({ allow_display_name: false, require_tld: false }).withMessage('Valid email required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { email, password, role } = req.body;

  // Check if email already exists
  db.get("SELECT id FROM users WHERE email = ?", [email.toLowerCase()], async (err, existingUser) => {
    if (err) return next(err);
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if ACTIVE invitation exists (pending/sent, not expired)
    db.get(
      "SELECT id, status FROM invitations WHERE email = ? AND organisation_id = ? AND status IN ('pending', 'sent') AND expires_at > datetime('now')",
      [email.toLowerCase(), req.user.organisationId],
      (err, existingInvitation) => {
        if (err) return next(err);
        if (existingInvitation) {
          return res.status(400).json({
            error: 'An active invitation already exists for this email. Please wait for the user to accept the invitation or delete it first.',
            invitationStatus: existingInvitation.status
          });
        }

        // Create user (owner or member) - no restriction on creating members
        // Owners can always create members regardless of how many owners exist
        const userId = generateUuid();
        bcrypt.hash(password, 10, (err, passwordHash) => {
          if (err) return next(err);

          db.run(
            "INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified) VALUES (?, ?, ?, ?, ?, ?)",
            [userId, email.toLowerCase(), passwordHash, req.user.organisationId, role, 0],
            (err) => {
              if (err) return next(err);
              res.json({ success: true, userId, email: email.toLowerCase(), role });
            }
          );
        });
      }
    );
  });
});

// PATCH Update User Role
router.patch('/api/admin/users/:userId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('userId').isUUID().withMessage('Invalid user ID'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { userId } = req.params;
  const { role } = req.body;

  // Cannot change own role
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot change your own role' });
  }

  // Verify user is in same organization
  db.get("SELECT id, role FROM users WHERE id = ? AND organisation_id = ?", [userId, req.user.organisationId], (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If changing from owner to member, check if this is the last owner
    if (user.role === 'owner' && role === 'member') {
      db.get("SELECT COUNT(*) as count FROM users WHERE organisation_id = ? AND role = 'owner'", [req.user.organisationId], (err, ownerCount) => {
        if (err) return next(err);
        if (ownerCount.count === 1) {
          return res.status(400).json({ error: 'Cannot remove last owner from organization' });
        }

        // Update role
        db.run("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [role, userId], (err) => {
          if (err) return next(err);
          res.json({ success: true });
        });
      });
    } else {
      // Update role
      db.run("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [role, userId], (err) => {
        if (err) return next(err);
        res.json({ success: true });
      });
    }
  });
});

// DELETE Remove User from Organization (Hard Delete with Cascade)
router.delete('/api/admin/users/:userId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('userId').isUUID().withMessage('Invalid user ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { userId } = req.params;

  // Cannot delete yourself
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }

  try {
    // Verify user is in same organization and get their info
    const user = await new Promise((resolve, reject) => {
      db.get("SELECT id, email, role, organisation_id FROM users WHERE id = ? AND organisation_id = ?",
        [userId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If deleting owner, check if this is the last owner
    if (user.role === 'owner') {
      const ownerCount = await new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM users WHERE organisation_id = ? AND role = 'owner'",
          [req.user.organisationId],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          }
        );
      });

      if (ownerCount.count === 1) {
        return res.status(400).json({ error: 'Cannot delete last owner from organization' });
      }
    }

    // Capture snapshot of user and their cards for audit
    const cards = await new Promise((resolve, reject) => {
      db.all("SELECT * FROM cards WHERE user_id = ?", [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });

    const userSettings = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM user_settings WHERE user_id = ?", [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    // Log to audit before deletion
    await logAudit(
      'user_deleted',
      'user',
      userId,
      {
        user: user,
        cards: cards,
        settings: userSettings,
        card_count: cards.length
      },
      req.user.id,
      req.user.organisationId
    );

    // TRUE HARD DELETE - foreign keys will CASCADE to all child records
    // This will automatically delete:
    // - cards (ON DELETE CASCADE)
    // - user_settings (ON DELETE CASCADE)
    // - password_reset_tokens (ON DELETE CASCADE)
    // - email_verification_tokens (ON DELETE CASCADE)
    // - invitations where user is inviter (ON DELETE CASCADE)
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log(`[USER DELETED] User ${user.email} deleted by ${req.user.email}, ${cards.length} cards cascaded`);

    res.json({
      success: true,
      deletedCards: cards.length
    });

  } catch (err) {
    console.error('[USER DELETE ERROR]', err);
    next(err);
  }
});

module.exports = router;
