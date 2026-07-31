const express = require('express');
const { body, param } = require('express-validator');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { db, dbRun } = require('../db');
const { JWT_SECRET, JWT_EXPIRES_IN, NODE_ENV, IS_DEMO_MODE } = require('../config/env');
const { apiLimiter, loginLimiter, publicReadLimiter, csrfProtection } = require('../config/security');
const { handleValidationErrors } = require('../middleware/validation');
const { requireAuth } = require('../middleware/auth');
const { generateUuid, generateSecureToken } = require('../lib/tokens');
const { getDefaultThemeColors } = require('../lib/themeColors');
const { sendPasswordResetEmail, sendVerificationEmail } = require('../lib/mailer');

const router = express.Router();

// CSRF token endpoint (public, before auth)
router.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Setup endpoints (public, only work if no users exist)
router.get('/api/setup/status', apiLimiter, (req, res, next) => {
  // In demo mode, setup is always considered complete
  if (IS_DEMO_MODE) {
    return res.json({
      setupComplete: true,
      userCount: 6, // 6 demo users
      demoMode: true
    });
  }

  db.get("SELECT COUNT(*) as count FROM users", [], (err, row) => {
    if (err) return next(err);
    res.json({
      setupComplete: row.count > 0,
      userCount: row.count,
      demoMode: false
    });
  });
});

// Demo mode status endpoint (public)
router.get('/api/demo/status', apiLimiter, (req, res) => {
  res.json({
    demoMode: IS_DEMO_MODE,
    resetInterval: 60, // minutes
    company: IS_DEMO_MODE ? 'Demon Straight' : null,
    credentials: IS_DEMO_MODE ? { email: 'alex@demonstraight.com', password: 'demo123' } : null
  });
});

router.post('/api/setup/initialize', apiLimiter, csrfProtection, [
  body('organisationName').trim().isLength({ min: 1, max: 200 }).withMessage('Organisation name is required and must be less than 200 characters'),
  body('adminEmail').isEmail({ allow_display_name: false, require_tld: false }).withMessage('Valid email required'),
  body('adminPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  // Only allow setup if no users exist
  db.get("SELECT COUNT(*) as count FROM users", [], async (err, row) => {
    if (err) return next(err);
    if (row.count > 0) {
      return res.status(403).json({ error: 'Setup already completed' });
    }

    const { organisationName, adminEmail, adminPassword } = req.body;

    // Generate organisation slug from name
    // Fix ReDoS: use separate replace calls instead of alternation in single regex
    const orgSlug = organisationName.toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+/, '')  // Remove leading dashes (no alternation)
      .replace(/-+$/, '')  // Remove trailing dashes (no alternation)
      || 'organisation';

    // Find available slug (shouldn't be needed on fresh install, but be safe)
    const findAvailableSlug = (slug, counter = 0) => {
      const finalSlug = counter === 0 ? slug : `${orgSlug}-${counter}`;
      db.get("SELECT id FROM organisations WHERE slug = ?", [finalSlug], (err, existingOrg) => {
        if (err) return next(err);
        if (existingOrg) {
          findAvailableSlug(slug, counter + 1);
        } else {
          createOrgAndUser(finalSlug);
        }
      });
    };

    findAvailableSlug(orgSlug);

    async function createOrgAndUser(slug) {
      const orgId = generateUuid();
      const userId = generateUuid();

      try {
        const passwordHash = await bcrypt.hash(adminPassword, 10);

        // Create organisation
        db.run(`
          INSERT INTO organisations (id, name, slug, subscription_tier)
          VALUES (?, ?, ?, ?)
        `, [orgId, organisationName, slug, 'individual'], (err) => {
          if (err) return next(err);

          // Create admin user
          db.run(`
            INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified)
            VALUES (?, ?, ?, ?, ?, ?)
          `, [userId, adminEmail.toLowerCase(), passwordHash, orgId, 'owner', 0], async (err) => {
            if (err) return next(err);

            // Initialize default organisation settings
            const defaultColors = getDefaultThemeColors();
            try {
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'default_organisation', organisationName]);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'theme_colors', JSON.stringify(defaultColors)]);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_theme_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_image_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_links_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_privacy_customisation', 'true']);
            } catch (err) {
              return next(err);
            }

            // Generate JWT token
            const token = jwt.sign(
              {
                user_id: userId,
                organisation_id: orgId,
                role: 'owner'
              },
              JWT_SECRET,
              { expiresIn: JWT_EXPIRES_IN }
            );

            // Set httpOnly cookie
            res.cookie('authToken', token, {
              httpOnly: true,
              secure: NODE_ENV === 'production',
              sameSite: 'strict',
              maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            res.json({ success: true, userId, email: adminEmail.toLowerCase(), role: 'owner' });
          });
        });
      } catch (err) {
        return next(err);
      }
    }
  });
});

// Login
router.post('/api/login', loginLimiter, [
  body('email').custom((value) => {
    // Allow localhost emails for development
    if (value && (validator.isEmail(value) || /^[^\s@]+@localhost(\.[^\s@]+)?$/.test(value))) {
      return true;
    }
    throw new Error('Valid email required');
  }),
  body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Look up user by email
    db.get("SELECT id, email, password_hash, organisation_id, role FROM users WHERE email = ?", [email.toLowerCase()], async (err, user) => {
      if (err) {
        return next(err);
      }

      // If no user found, return error
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Generate JWT token
      const token = jwt.sign(
        {
          user_id: user.id,
          organisation_id: user.organisation_id,
          role: user.role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Set httpOnly cookie
      res.cookie('authToken', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });

      res.json({ success: true });
    });
  } catch (err) {
    next(err);
  }
});

// Logout
router.post('/api/logout', (req, res) => {
  res.clearCookie('authToken');
  res.json({ success: true });
});

// GET Current User Info
router.get('/api/auth/me', requireAuth, apiLimiter, (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.get(
    `SELECT u.id, u.email, u.organisation_id, u.role, u.email_verified, o.slug as org_slug
     FROM users u LEFT JOIN organisations o ON u.organisation_id = o.id
     WHERE u.id = ?`,
    [req.user.id],
    (err, user) => {
      if (err) return next(err);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({
        id: user.id,
        email: user.email,
        organisationId: user.organisation_id,
        role: user.role,
        emailVerified: user.email_verified === 1,
        orgSlug: user.org_slug || null
      });
    }
  );
});

// --- PASSWORD RESET ENDPOINTS ---

// POST Forgot Password (Request password reset)
router.post('/api/auth/forgot-password', apiLimiter, [
  body('email').isEmail().withMessage('Valid email required')
], handleValidationErrors, async (req, res, next) => {
  const { email } = req.body;
  const emailLower = email.toLowerCase();

  // Find user by email
  db.get("SELECT id, email FROM users WHERE email = ?", [emailLower], async (err, user) => {
    if (err) return next(err);

    // Always return success (don't reveal if email exists)
    if (!user) {
      return res.json({ success: true, message: 'If an account exists with this email, a password reset link has been sent' });
    }

    // Generate secure token
    const token = generateSecureToken(32);
    const tokenId = generateUuid();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry

    // Delete any existing unused tokens for this user
    db.run("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", [user.id], (err) => {
      if (err) {
        console.error('Error deleting old tokens:', err);
        // Continue anyway
      }

      // Create password reset token
      db.run(
        "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
        [tokenId, user.id, token, expiresAt.toISOString()],
        async (err) => {
          if (err) return next(err);

          try {
            await sendPasswordResetEmail({ to: emailLower, token });
          } catch (emailErr) {
            console.error('Failed to send password reset email:', emailErr);
            // Don't fail the request if email fails
          }

          res.json({ success: true, message: 'If an account exists with this email, a password reset link has been sent' });
        }
      );
    });
  });
});

// POST Reset Password (with token)
router.post('/api/auth/reset-password', apiLimiter, [
  body('token').isLength({ min: 64, max: 64 }).withMessage('Invalid reset token'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  const { token, password } = req.body;

  // Get reset token
  db.get(
    "SELECT prt.*, u.id as user_id FROM password_reset_tokens prt JOIN users u ON prt.user_id = u.id WHERE prt.token = ?",
    [token],
    async (err, resetToken) => {
      if (err) return next(err);
      if (!resetToken) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }
      if (resetToken.used_at) {
        return res.status(400).json({ error: 'This reset token has already been used' });
      }
      if (new Date(resetToken.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Reset token has expired' });
      }

      // Hash new password
      const passwordHash = await bcrypt.hash(password, 10);

      // Update user password
      db.run(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [passwordHash, resetToken.user_id],
        (err) => {
          if (err) return next(err);

          // Mark token as used
          db.run(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
            [resetToken.id],
            (err) => {
              if (err) {
                console.error('Failed to mark token as used:', err);
                // Don't fail the request
              }

              res.json({ success: true, message: 'Password has been reset successfully' });
            }
          );
        }
      );
    }
  );
});

// POST Change Password (when logged in)
router.post('/api/auth/change-password', requireAuth, apiLimiter, csrfProtection, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { currentPassword, newPassword } = req.body;

  // Get user
  db.get("SELECT password_hash FROM users WHERE id = ?", [req.user.id], async (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // Update password
    db.run(
      "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [passwordHash, req.user.id],
      (err) => {
        if (err) return next(err);
        res.json({ success: true, message: 'Password has been changed successfully' });
      }
    );
  });
});

// --- EMAIL VERIFICATION ENDPOINTS ---

// POST Send Verification Email
router.post('/api/auth/send-verification', requireAuth, apiLimiter, csrfProtection, async (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Get user email
  db.get("SELECT email, email_verified FROM users WHERE id = ?", [req.user.id], async (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    // Check for existing unused verification token
    db.get(
      "SELECT id FROM email_verification_tokens WHERE user_id = ? AND verified_at IS NULL AND expires_at > datetime('now')",
      [req.user.id],
      async (err, existingToken) => {
        if (err) return next(err);
        if (existingToken) {
          return res.status(400).json({ error: 'Verification email already sent. Please check your email or wait before requesting another.' });
        }

        // Generate verification token
        const token = generateSecureToken(32);
        const tokenId = generateUuid();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiry

        // Create verification token
        db.run(
          "INSERT INTO email_verification_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
          [tokenId, req.user.id, token, expiresAt.toISOString()],
          async (err) => {
            if (err) return next(err);

            try {
              await sendVerificationEmail({ to: user.email, token });
            } catch (emailErr) {
              console.error('Failed to send verification email:', emailErr);
              return res.status(500).json({ error: 'Failed to send verification email' });
            }

            res.json({ success: true, message: 'Verification email sent' });
          }
        );
      }
    );
  });
});

// GET Verify Email (with token)
router.get('/api/auth/verify-email/:token', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid verification token')
], handleValidationErrors, (req, res, next) => {
  const { token } = req.params;

  // Get verification token
  db.get(
    "SELECT evt.*, u.id as user_id, u.email FROM email_verification_tokens evt JOIN users u ON evt.user_id = u.id WHERE evt.token = ?",
    [token],
    (err, verificationToken) => {
      if (err) return next(err);
      if (!verificationToken) {
        return res.status(400).json({ error: 'Invalid or expired verification token' });
      }
      if (verificationToken.verified_at) {
        return res.status(400).json({ error: 'Email has already been verified' });
      }
      if (new Date(verificationToken.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Verification token has expired' });
      }

      // Mark email as verified
      db.run(
        "UPDATE users SET email_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [verificationToken.user_id],
        (err) => {
          if (err) return next(err);

          // Mark token as verified
          db.run(
            "UPDATE email_verification_tokens SET verified_at = CURRENT_TIMESTAMP WHERE id = ?",
            [verificationToken.id],
            (err) => {
              if (err) {
                console.error('Failed to mark token as verified:', err);
                // Don't fail the request
              }

              res.json({ success: true, message: 'Email verified successfully' });
            }
          );
        }
      );
    }
  );
});

module.exports = router;
