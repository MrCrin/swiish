const express = require('express');
const { body } = require('express-validator');
const { db } = require('../db');
const { apiLimiter, csrfProtection } = require('../config/security');
const { handleValidationErrors } = require('../middleware/validation');
const { requireAuth, requireRole } = require('../middleware/auth');
const { log } = require('../lib/logger');
const { getDefaultThemeColors } = require('../lib/themeColors');
const { getPublicSettingsByOrgSlug } = require('../services/settingsService');

const router = express.Router();

// GET Public Settings (theme_colors, theme_variant, and default_organisation, no auth required)
// Returns settings from specified organization or default organization
// Accepts optional ?orgSlug= parameter to get settings for a specific organization
router.get('/api/settings', apiLimiter, (req, res, next) => {
  const orgSlug = req.query.orgSlug || 'default';

  getPublicSettingsByOrgSlug(orgSlug, (err, settings) => {
    if (err) {
      return next(err);
    }
    res.json(settings);
  });
});

// GET Settings (Admin - full settings)
router.get('/api/admin/settings', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  // Ensure user is authenticated and has organization
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all("SELECT key, value FROM organisation_settings WHERE organisation_id = ?", [req.user.organisationId], (err, rows) => {
    if (err) {
      log('GET /api/admin/settings - Database error', { error: err.message });
      return next(err);
    }

    log('GET /api/admin/settings - Raw database rows', {
      organisationId: req.user.organisationId,
      rows: rows.map(r => ({ key: r.key, value: r.value }))
    });

    const settings = {};
    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings[row.key] = JSON.parse(row.value);
        } else if (row.key.startsWith('allow_')) {
          // Convert string "true"/"false" to boolean for override toggles
          settings[row.key] = row.value === 'true';
        } else {
          settings[row.key] = row.value;
        }
      } catch (e) {
        log(`Error parsing setting ${row.key}`, { error: e.message, value: row.value });
      }
    });

    // Ensure defaults exist
    if (!settings.default_organisation) {
      settings.default_organisation = 'My Organisation';
    }
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) {
      settings.theme_variant = 'swiish';
    }
    // Ensure override toggles have defaults (true = allow customisation)
    if (settings.allow_theme_customisation === undefined) {
      settings.allow_theme_customisation = true;
    }
    if (settings.allow_image_customisation === undefined) {
      settings.allow_image_customisation = true;
    }
    if (settings.allow_links_customisation === undefined) {
      settings.allow_links_customisation = true;
    }
    if (settings.allow_privacy_customisation === undefined) {
      settings.allow_privacy_customisation = true;
    }

    log('GET /api/admin/settings - Returning settings', {
      organisationId: req.user.organisationId,
      settings: {
        default_organisation: settings.default_organisation,
        theme_variant: settings.theme_variant,
        allow_theme_customisation: settings.allow_theme_customisation,
        allow_image_customisation: settings.allow_image_customisation,
        allow_links_customisation: settings.allow_links_customisation,
        allow_privacy_customisation: settings.allow_privacy_customisation,
        theme_colors_count: settings.theme_colors?.length
      }
    });

    res.json(settings);
  });
});

// POST Settings (Update)
router.post('/api/admin/settings', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('default_organisation').optional().trim().isLength({ max: 200 }).withMessage('Organisation name too long'),
  body('theme_colors').optional().isArray().withMessage('Theme colors must be an array'),
  body('theme_colors.*.name').optional().trim().isLength({ max: 50 }).withMessage('Color name too long'),
  body('theme_colors.*.gradient').optional().trim().isLength({ max: 200 }).withMessage('Gradient too long'),
  body('theme_colors.*.button').optional().trim().isLength({ max: 200 }).withMessage('Button classes too long'),
  body('theme_colors.*.link').optional().trim().isLength({ max: 200 }).withMessage('Link classes too long'),
  body('theme_colors.*.text').optional().trim().isLength({ max: 200 }).withMessage('Text classes too long'),
  // Add validation for hex color properties
  body('theme_colors.*.gradientStyle').optional().trim().isLength({ max: 500 }).withMessage('Gradient style too long'),
  body('theme_colors.*.buttonStyle').optional().trim().isLength({ max: 50 }).withMessage('Button style too long'),
  body('theme_colors.*.linkStyle').optional().trim().isLength({ max: 50 }).withMessage('Link style too long'),
  body('theme_colors.*.textStyle').optional().trim().isLength({ max: 50 }).withMessage('Text style too long'),
  body('theme_colors.*.colorType').optional().isIn(['standard', 'custom']).withMessage('Invalid color type'),
  body('theme_colors.*.hexBase').optional().custom((value) => {
    if (value === null || value === undefined || value === '') return true;
    return /^#[0-9A-Fa-f]{6}$/.test(value);
  }).withMessage('Invalid hex base color'),
  body('theme_colors.*.hexSecondary').optional().custom((value) => {
    if (value === null || value === undefined || value === '') return true;
    return /^#[0-9A-Fa-f]{6}$/.test(value);
  }).withMessage('Invalid hex secondary color'),
  body('theme_colors.*.baseColor').optional().trim().isLength({ max: 50 }).withMessage('Base color too long'),
  body('theme_colors.*.secondaryColor').optional().trim().isLength({ max: 50 }).withMessage('Secondary color too long'),
  body('theme_colors.*.shade').optional().isInt({ min: 100, max: 900 }).withMessage('Invalid shade'),
  // Validation for override toggles
  body('allow_theme_customisation').optional().isBoolean().withMessage('allow_theme_customisation must be a boolean'),
  body('allow_image_customisation').optional().isBoolean().withMessage('allow_image_customisation must be a boolean'),
  body('allow_links_customisation').optional().isBoolean().withMessage('allow_links_customisation must be a boolean'),
  body('allow_privacy_customisation').optional().isBoolean().withMessage('allow_privacy_customisation must be a boolean')
], handleValidationErrors, (req, res, next) => {
  // Ensure user is authenticated and has organization
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const {
    default_organisation,
    theme_colors,
    theme_variant,
    allow_theme_customisation,
    allow_image_customisation,
    allow_links_customisation,
    allow_privacy_customisation
  } = req.body;

  log('POST /api/admin/settings - Received settings update', {
    organisationId: req.user.organisationId,
    default_organisation,
    allow_theme_customisation,
    allow_image_customisation,
    allow_links_customisation,
    allow_privacy_customisation,
    theme_variant,
    theme_colors_count: theme_colors?.length
  });

  // Use promises to wait for all database operations to complete
  const promises = [];

  if (default_organisation !== undefined) {
    const sanitized = default_organisation.trim().substring(0, 200);
    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'default_organisation', sanitized],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }

  if (theme_colors !== undefined && Array.isArray(theme_colors)) {
    // Sanitize theme colors - preserve ALL properties, not just Tailwind classes
    const sanitized = theme_colors.map(color => {
      const sanitizedColor = {
        name: (color.name || '').trim().substring(0, 50),
        // Preserve Tailwind classes (may be null for hex colors)
        gradient: color.gradient ? (color.gradient || '').trim().substring(0, 200) : null,
        button: color.button ? (color.button || '').trim().substring(0, 200) : null,
        link: color.link ? (color.link || '').trim().substring(0, 200) : null,
        text: color.text ? (color.text || '').trim().substring(0, 200) : null,
        // Preserve hex styles (may be null for Tailwind colors)
        gradientStyle: color.gradientStyle || null,
        buttonStyle: color.buttonStyle || null,
        linkStyle: color.linkStyle || null,
        textStyle: color.textStyle || null,
        // Preserve color type and hex values
        colorType: color.colorType || null,
        hexBase: color.hexBase || null,
        hexSecondary: color.hexSecondary || null,
        // Preserve base color metadata
        baseColor: color.baseColor || null,
        secondaryColor: color.secondaryColor || null,
        shade: color.shade || null
      };
      return sanitizedColor;
    });

    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'theme_colors', JSON.stringify(sanitized)],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }

  if (theme_variant !== undefined) {
    const variant = typeof theme_variant === 'string' ? theme_variant.trim().substring(0, 50) : 'swiish';
    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'theme_variant', variant],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }

  // Save override toggles (convert boolean to "true"/"false" string for storage)
  const saveToggle = (key, value) => {
    if (value !== undefined && typeof value === 'boolean') {
      promises.push(new Promise((resolve, reject) => {
        db.run(
          "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
          [req.user.organisationId, key, value ? 'true' : 'false'],
          (err) => {
            if (err) return reject(err);
            resolve();
          }
        );
      }));
    }
  };

  saveToggle('allow_theme_customisation', allow_theme_customisation);
  saveToggle('allow_image_customisation', allow_image_customisation);
  saveToggle('allow_links_customisation', allow_links_customisation);
  saveToggle('allow_privacy_customisation', allow_privacy_customisation);

  // Wait for all database operations to complete before sending response
  Promise.all(promises)
    .then(() => {
      log('POST /api/admin/settings - Successfully saved all settings', {
        organisationId: req.user.organisationId,
        promisesCompleted: promises.length
      });
      res.json({ success: true });
    })
    .catch((err) => {
      log('POST /api/admin/settings - Error saving settings', { error: err.message, stack: err.stack });
      next(err);
    });
});

module.exports = router;
