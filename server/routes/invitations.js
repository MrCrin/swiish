const express = require('express');
const { body, param } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { db } = require('../db');
const { JWT_SECRET, JWT_EXPIRES_IN, NODE_ENV } = require('../config/env');
const { apiLimiter, publicReadLimiter, csrfProtection } = require('../config/security');
const { handleValidationErrors } = require('../middleware/validation');
const { requireAuth, requireRole } = require('../middleware/auth');
const { generateUuid, generateSecureToken } = require('../lib/tokens');
const { logAudit } = require('../lib/audit');
const { sendInvitationEmail } = require('../lib/mailer');

const router = express.Router();

// --- INVITATION ENDPOINTS ---

// POST Create and Send Invitation
router.post('/api/admin/invitations', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('email').isEmail().withMessage('Valid email required'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { email, role } = req.body;
  const emailLower = email.toLowerCase();

  try {
    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM users WHERE email = ?", [emailLower], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if ACTIVE invitation exists (pending/sent, not expired)
    // NOTE: This allows retries after failed/expired invitations
    const existingInvitation = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, status FROM invitations WHERE email = ? AND organisation_id = ? AND status IN ('pending', 'sent') AND expires_at > datetime('now')",
        [emailLower, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existingInvitation) {
      return res.status(400).json({
        error: 'Active invitation already exists for this email',
        status: existingInvitation.status
      });
    }

    // Generate secure token
    const token = generateSecureToken(32);
    const invitationId = generateUuid();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Create invitation with status='pending' first
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO invitations (id, organisation_id, email, token, role, invited_by, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
        [invitationId, req.user.organisationId, emailLower, token, role, req.user.id, expiresAt.toISOString()],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Get organization name for email
    const org = await new Promise((resolve, reject) => {
      db.get("SELECT name FROM organisations WHERE id = ?", [req.user.organisationId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    const orgName = org ? org.name : 'Organization';

    // Attempt to send email
    let emailStatus = 'sent';
    let emailError = null;

    try {
      await sendInvitationEmail({ to: emailLower, orgName, token });
    } catch (emailErr) {
      console.error('Failed to send invitation email:', emailErr);
      emailStatus = 'failed';
      emailError = emailErr.message;
    }

    // Update invitation status
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE invitations SET status = ? WHERE id = ?",
        [emailStatus, invitationId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Log audit event
    await logAudit(
      'invitation_created',
      'invitation',
      invitationId,
      { email: emailLower, role, status: emailStatus },
      req.user.id,
      req.user.organisationId
    );

    // Return success with status info
    res.json({
      success: true,
      invitationId,
      expiresAt: expiresAt.toISOString(),
      status: emailStatus,
      ...(emailError && { warning: 'Invitation created but email failed to send. You can retry from the admin panel.' })
    });

  } catch (err) {
    next(err);
  }
});

// GET Invitation Details (Public)
router.get('/api/invitations/:token', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid invitation token')
], handleValidationErrors, (req, res, next) => {
  const { token } = req.params;

  db.get(
    "SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, o.name as organization_name FROM invitations i JOIN organisations o ON i.organisation_id = o.id WHERE i.token = ?",
    [token],
    (err, invitation) => {
      if (err) return next(err);
      if (!invitation) {
        return res.status(404).json({ error: 'Invitation not found' });
      }
      if (invitation.accepted_at) {
        return res.status(400).json({ error: 'Invitation has already been accepted' });
      }
      if (new Date(invitation.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Invitation has expired' });
      }
      res.json({
        email: invitation.email,
        role: invitation.role,
        organisationName: invitation.organization_name,
        expiresAt: invitation.expires_at
      });
    }
  );
});

// POST Accept Invitation
router.post('/api/invitations/:token/accept', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid invitation token'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  const { token } = req.params;
  const { password } = req.body;

  // Get invitation
  db.get(
    "SELECT * FROM invitations WHERE token = ?",
    [token],
    async (err, invitation) => {
      if (err) return next(err);
      if (!invitation) {
        return res.status(404).json({ error: 'Invitation not found' });
      }
      if (invitation.accepted_at) {
        return res.status(400).json({ error: 'Invitation has already been accepted' });
      }
      if (new Date(invitation.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Invitation has expired' });
      }

      // Check if user already exists
      db.get("SELECT id FROM users WHERE email = ?", [invitation.email], async (err, existingUser) => {
        if (err) return next(err);
        if (existingUser) {
          return res.status(400).json({ error: 'User with this email already exists' });
        }

        // Create user
        const userId = generateUuid();
        const passwordHash = await bcrypt.hash(password, 10);

        db.run(
          "INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified) VALUES (?, ?, ?, ?, ?, ?)",
          [userId, invitation.email, passwordHash, invitation.organisation_id, invitation.role, 0],
          (err) => {
            if (err) return next(err);

            // Mark invitation as accepted
            db.run(
              "UPDATE invitations SET accepted_at = CURRENT_TIMESTAMP, status = 'accepted' WHERE id = ?",
              [invitation.id],
              async (err) => {
                if (err) {
                  console.error('Failed to mark invitation as accepted:', err);
                  // Don't fail the request
                } else {
                  // Log audit event for invitation acceptance
                  try {
                    await logAudit(
                      'invitation_accepted',
                      'invitation',
                      invitation.id,
                      { email: invitation.email, role: invitation.role },
                      userId,
                      invitation.organisation_id
                    );
                  } catch (auditErr) {
                    console.error('Failed to log invitation acceptance audit:', auditErr);
                    // Don't fail the request if audit logging fails
                  }
                }

                // Generate JWT token
                const jwtToken = jwt.sign(
                  {
                    user_id: userId,
                    organisation_id: invitation.organisation_id,
                    role: invitation.role
                  },
                  JWT_SECRET,
                  { expiresIn: JWT_EXPIRES_IN }
                );

                // Set httpOnly cookie
                res.cookie('authToken', jwtToken, {
                  httpOnly: true,
                  secure: NODE_ENV === 'production',
                  sameSite: 'strict',
                  maxAge: 24 * 60 * 60 * 1000 // 24 hours
                });

                res.json({ success: true, userId, email: invitation.email, role: invitation.role });
              }
            );
          }
        );
      });
    }
  );
});

// --- INVITATION MANAGEMENT ENDPOINTS ---

// GET List all invitations for organization
router.get('/api/admin/invitations', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all(
    `SELECT
      i.id,
      i.email,
      i.role,
      i.status,
      i.created_at,
      i.expires_at,
      i.accepted_at,
      u.email as invited_by_email
    FROM invitations i
    LEFT JOIN users u ON i.invited_by = u.id
    WHERE i.organisation_id = ?
    ORDER BY i.created_at DESC`,
    [req.user.organisationId],
    (err, invitations) => {
      if (err) return next(err);
      res.json({ invitations });
    }
  );
});

// DELETE Cancel invitation
router.delete('/api/admin/invitations/:invitationId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('invitationId').isUUID().withMessage('Invalid invitation ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { invitationId } = req.params;

  try {
    // Verify invitation belongs to organization
    const invitation = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, email, status, accepted_at FROM invitations WHERE id = ? AND organisation_id = ?",
        [invitationId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!invitation) {
      return res.status(404).json({ error: 'Invitation not found' });
    }

    // Don't allow deletion of accepted invitations (for audit trail)
    if (invitation.accepted_at) {
      return res.status(400).json({ error: 'Cannot delete accepted invitation' });
    }

    // Log audit before deletion
    await logAudit(
      'invitation_deleted',
      'invitation',
      invitationId,
      { email: invitation.email, status: invitation.status },
      req.user.id,
      req.user.organisationId
    );

    // Delete invitation
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM invitations WHERE id = ?", [invitationId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.json({ success: true });

  } catch (err) {
    next(err);
  }
});

// POST Retry sending failed invitation
router.post('/api/admin/invitations/:invitationId/retry', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('invitationId').isUUID().withMessage('Invalid invitation ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { invitationId } = req.params;

  try {
    // Get invitation
    const invitation = await new Promise((resolve, reject) => {
      db.get(
        `SELECT i.*, o.name as org_name
         FROM invitations i
         JOIN organisations o ON i.organisation_id = o.id
         WHERE i.id = ? AND i.organisation_id = ?`,
        [invitationId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!invitation) {
      return res.status(404).json({ error: 'Invitation not found' });
    }

    // Only allow retry for failed or pending invitations
    if (invitation.status !== 'failed' && invitation.status !== 'pending') {
      return res.status(400).json({ error: `Cannot retry invitation with status: ${invitation.status}` });
    }

    // Check if expired
    if (new Date(invitation.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invitation has expired. Please delete and create a new one.' });
    }

    // Attempt to send email
    let emailStatus = 'sent';
    let emailError = null;

    try {
      await sendInvitationEmail({ to: invitation.email, orgName: invitation.org_name, token: invitation.token });
    } catch (emailErr) {
      console.error('Failed to send invitation email:', emailErr);
      emailStatus = 'failed';
      emailError = emailErr.message;
    }

    // Update invitation status
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE invitations SET status = ? WHERE id = ?",
        [emailStatus, invitationId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Log audit
    await logAudit(
      'invitation_retry',
      'invitation',
      invitationId,
      { email: invitation.email, new_status: emailStatus },
      req.user.id,
      req.user.organisationId
    );

    res.json({
      success: emailStatus === 'sent',
      status: emailStatus,
      ...(emailError && { error: 'Email failed to send. Please check SMTP configuration.' })
    });

  } catch (err) {
    next(err);
  }
});

module.exports = router;
