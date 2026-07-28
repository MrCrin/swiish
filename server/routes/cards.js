const express = require('express');
const fs = require('fs');
const path = require('path');
const { param } = require('express-validator');
const validator = require('validator');
const { db } = require('../db');
const { SHORT_CODE_LENGTH } = require('../config/env');
const { apiLimiter, cardReadLimiter, csrfProtection } = require('../config/security');
const { handleValidationErrors, slugValidation, cardDataValidation } = require('../middleware/validation');
const { requireAuth, requireRole } = require('../middleware/auth');
const { log } = require('../lib/logger');
const { PREVIEW_CACHE_MAX_AGE, resolveCachePath, writeToCacheAtomic, invalidatePreviewCache } = require('../lib/previewCache');
const { generateGenericPreviewImage, generatePreviewImage } = require('../lib/previewImage');
const { getOrganizationSettings } = require('../services/settingsService');
const { upsertCard } = require('../services/cardService');

const router = express.Router();

// GET All Cards (Admin Dashboard)
router.get('/api/admin/cards', requireAuth, apiLimiter, (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Owners see all cards in organisation, members see only their own
  let query, params;
  const isOwner = req.user.role === 'owner';

  if (isOwner && req.user.organisationId) {
    // First, ensure organisation has a slug - if not, generate and save it
    db.get("SELECT slug, name FROM organisations WHERE id = ?", [req.user.organisationId], (err, orgRow) => {
      if (err) return next(err);

      let orgSlug = orgRow?.slug;
      // If organization doesn't have a slug, generate one from the organization name
      if (!orgSlug && orgRow?.name) {
        // Fix ReDoS: use separate replace calls instead of alternation in single regex
        const generatedSlug = orgRow.name.toLowerCase()
          .trim()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+/, '')  // Remove leading dashes (no alternation)
          .replace(/-+$/, '')  // Remove trailing dashes (no alternation)
          || 'organization';
        // Update organization with generated slug
        db.run("UPDATE organisations SET slug = ? WHERE id = ?", [generatedSlug, req.user.organisationId], (err) => {
          if (err) return next(err);
          orgSlug = generatedSlug;
          executeQuery(orgSlug);
        });
      } else {
        executeQuery(orgSlug);
      }

      function executeQuery(orgSlugValue) {
        // Owner with organization: get all users and their cards (LEFT JOIN to include users without cards)
        const query = `
          SELECT
            u.id as user_id,
            u.email as user_email,
            u.role as user_role,
            u.created_at as user_created_at,
            c.slug,
            c.short_code,
            c.data
          FROM users u
          LEFT JOIN cards c ON c.user_id = u.id
          WHERE u.organisation_id = ?
          ORDER BY u.created_at DESC, c.created_at DESC
        `;
        const params = [req.user.organisationId];

        db.all(query, params, (err, rows) => {
          if (err) {
            log('GET /api/admin/cards - ERROR', { error: err.message, userId: req.user.id, role: req.user.role });
            return next(err);
          }

          log('GET /api/admin/cards - Query result', {
            isOwner,
            organisationId: req.user.organisationId,
            orgSlug: orgSlugValue,
            queryUsed: 'org-query',
            rowCount: rows.length,
            firstRowKeys: rows.length > 0 ? Object.keys(rows[0]) : [],
            firstRowSample: rows.length > 0 ? rows[0] : null
          });

          const list = rows.map(row => {
            // For owners with organization, we use LEFT JOIN so users without cards have row.data = null
            // User info is always present (from users table)
            const result = {
              userId: row.user_id,
              userEmail: row.user_email,
              userRole: row.user_role,
              userCreatedAt: row.user_created_at,
              slug: row.slug || null,
              shortCode: row.short_code || null,
              orgSlug: orgSlugValue || null,
              name: '',
              title: '',
              avatar: null,
              email: ''
            };

            // If user has a card, parse the card data
            if (row.slug && row.data) {
              try {
                const parsed = JSON.parse(row.data);
                result.name = `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim();
                result.title = parsed.personal?.title || '';
                result.avatar = parsed.images?.avatar || null;
                result.email = (parsed.contact?.email || '').toLowerCase();
              } catch (e) {
                result.name = 'Invalid card data';
                result.email = row.user_email;
              }
            } else {
              // User has no cards - leave name empty
              result.name = '';
              result.email = row.user_email;
            }

            return result;
          });

          log('GET /api/admin/cards - Response', {
            count: list.length,
            hasUserEmail: !!list[0]?.userEmail,
            userEmail: list[0]?.userEmail,
            userId: list[0]?.userId,
            userRole: list[0]?.userRole,
            orgSlug: list[0]?.orgSlug
          });
          res.json(list);
        });
      }
    });

    return; // Exit early, we'll handle the response in the callback
  } else if (isOwner) {
    // Owner without organization: get own cards with user info
    query = `
      SELECT c.slug, c.short_code, c.data, c.user_id, u.email as user_email, u.role as user_role, u.created_at as user_created_at, o.slug as org_slug
      FROM cards c
      JOIN users u ON c.user_id = u.id
      LEFT JOIN organisations o ON u.organisation_id = o.id
      WHERE c.user_id = ?
      ORDER BY c.created_at DESC
    `;
    params = [req.user.id];
  } else {
    // Member: get own cards only (no user info needed)
    query = `
      SELECT c.slug, c.short_code, c.data, o.slug as org_slug
      FROM cards c
      JOIN users u ON c.user_id = u.id
      LEFT JOIN organisations o ON u.organisation_id = o.id
      WHERE c.user_id = ?
    `;
    params = [req.user.id];
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      log('GET /api/admin/cards - ERROR', { error: err.message, userId: req.user.id, role: req.user.role });
      return next(err);
    }

    log('GET /api/admin/cards - Query result', {
      isOwner,
      organisationId: req.user.organisationId,
      queryUsed: isOwner && req.user.organisationId ? 'org-query' : isOwner ? 'owner-query' : 'member-query',
      rowCount: rows.length,
      firstRowKeys: rows.length > 0 ? Object.keys(rows[0]) : [],
      firstRowSample: rows.length > 0 ? rows[0] : null  // Log the entire first row
    });

    const list = rows.map(row => {
      // For owners with organization, we use LEFT JOIN so users without cards have row.data = null
      if (isOwner && req.user.organisationId) {
        // User info is always present (from users table)
        // Ensure orgSlug is set - if null, we'll need to generate it or use a default
        let orgSlug = row.org_slug;
        // If org slug is null, try to get it from the organization
        if (!orgSlug && req.user.organisationId) {
          // This shouldn't happen if JOIN worked, but handle it just in case
          // We'll leave it as null and handle in frontend
        }

        const result = {
          userId: row.user_id,
          userEmail: row.user_email,
          userRole: row.user_role,
          userCreatedAt: row.user_created_at,
          slug: row.slug || null,
          shortCode: row.short_code || null,
          orgSlug: orgSlug || null,
          name: '',
          title: '',
          avatar: null,
          email: ''
        };

        // If user has a card, parse the card data
        if (row.slug && row.data) {
          try {
            const parsed = JSON.parse(row.data);
            result.name = `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim();
            result.title = parsed.personal?.title || '';
            result.avatar = parsed.images?.avatar || null;
            result.email = (parsed.contact?.email || '').toLowerCase();
          } catch (e) {
            result.name = 'Invalid card data';
            result.email = row.user_email;
          }
        } else {
          // User has no cards - leave name empty
          result.name = '';
          result.email = row.user_email;
        }

        return result;
      }

      // For other cases (owner without org, or member), use original logic
      try {
        const parsed = JSON.parse(row.data);
        const result = {
          slug: row.slug,
          shortCode: row.short_code || null,
          orgSlug: row.org_slug || null,
          name: `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim(),
          title: parsed.personal?.title || '',
          avatar: parsed.images?.avatar || null,
          email: (parsed.contact?.email || '').toLowerCase()
        };

        // Add user info for owners (from JOIN query)
        if (isOwner && row.user_id) {
          result.userId = row.user_id;
          result.userEmail = row.user_email;
          result.userRole = row.user_role;
          result.userCreatedAt = row.user_created_at;
          result.orgSlug = row.org_slug || null;
        }

        return result;
      } catch (e) {
        const result = {
          slug: row.slug,
          shortCode: row.short_code || null,
          orgSlug: row.org_slug || null,
          name: 'Invalid data',
          title: '',
          avatar: null,
          email: ''
        };

        if (isOwner && row.user_id) {
          result.userId = row.user_id;
          result.userEmail = row.user_email;
          result.userRole = row.user_role;
          result.userCreatedAt = row.user_created_at;
        }

        return result;
      }
    });

    log('GET /api/admin/cards - Response', {
      count: list.length,
      hasUserInfo: list.filter(c => c.userEmail).length,
      sampleCard: list.length > 0 ? {
        slug: list[0].slug,
        hasUserEmail: !!list[0].userEmail,
        userEmail: list[0].userEmail,
        userId: list[0].userId,
        userRole: list[0].userRole
      } : null
    });
    res.json(list);
  });
});

// GET Short Code Card (Public endpoint - short code lookup)
// MUST come FIRST before other /api/cards routes to avoid route conflicts
router.get('/api/cards/short/:shortCode', cardReadLimiter, (req, res, next) => {
  const shortCode = (req.params.shortCode || '').trim();
  log(`[API] GET /api/cards/short/${shortCode} - Request received`);

  // Validate: exactly 7 alphanumeric characters
  if (!shortCode || shortCode.length !== 7) {
    log(`[API] Short code validation failed: length=${shortCode?.length || 0}`);
    return res.status(400).json({ error: `Short code must be exactly ${SHORT_CODE_LENGTH} characters` });
  }

  if (!new RegExp(`^[a-zA-Z0-9]{${SHORT_CODE_LENGTH}}$`).test(shortCode)) {
    log(`[API] Short code validation failed: invalid format`);
    return res.status(400).json({ error: 'Short code must contain only letters and numbers' });
  }

  log(`[API] Short code validated, querying database...`);
  // Short codes are case-sensitive, so use exact match
  // Also get organization slug so frontend can fetch correct settings
  db.get(`
    SELECT c.data, c.short_code, o.slug as org_slug
    FROM cards c
    JOIN users u ON c.user_id = u.id
    LEFT JOIN organisations o ON u.organisation_id = o.id
    WHERE c.short_code = ?
  `, [shortCode], (err, row) => {
    if (err) {
      console.error('[API] Database error fetching short code:', err);
      return next(err);
    }
    if (!row) {
      log(`[API] Short code not found in database: ${shortCode}`);
      return res.status(404).json({ error: "Card not found" });
    }
    try {
      const cardData = JSON.parse(row.data);
      // Include short_code and org_slug in response for frontend
      cardData._shortCode = row.short_code;
      if (row.org_slug) {
        cardData._orgSlug = row.org_slug;
      }
      log(`[API] Short code found, returning card data (has personal: ${!!cardData.personal}, org_slug: ${row.org_slug})`);
      res.json(cardData);
    } catch (e) {
      console.error('[API] Error parsing card data:', e);
      next(e);
    }
  });
});

// GET Card Preview Image (Social Media Meta Tag)
// MUST come BEFORE org-scoped route so /preview.png matches before being interpreted as cardSlug
// Supports both slug and short_code identifiers
// Route pattern: /api/cards/:identifier/preview.png
router.get('/api/cards/:identifier/preview.png', cardReadLimiter, [
  param('identifier').trim().matches(/^[a-zA-Z0-9-]+$/).withMessage('Invalid identifier')
], handleValidationErrors, async (req, res, next) => {
  try {
    const identifier = req.params.identifier; // Keep original case for short_code lookup
    const identifierLower = identifier.toLowerCase(); // For slug lookup

    // Check cache first (use lowercase for cache key)
    const cachedPath = resolveCachePath(identifierLower);
    if (cachedPath) {
      try {
        const stat = await fs.promises.stat(cachedPath);
        // Check cache age (24 hours)
        if (Date.now() - stat.mtimeMs < PREVIEW_CACHE_MAX_AGE) {
          const cachedBuffer = await fs.promises.readFile(cachedPath);
          res.set({
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=0, must-revalidate', // Always revalidate with ETag
            'ETag': `"${stat.mtime.getTime()}"`,
            'Pragma': 'no-cache'
          });
          return res.send(cachedBuffer);
        }
      } catch (err) {
        // Cache miss or stat error, proceed to generate
        if (err.code !== 'ENOENT') {
          console.error('[Preview] Cache stat error:', err.message);
        }
      }
    }

    // Try to find card by short_code first (exact match)
    let cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code, c.slug, u.organisation_id
        FROM cards c
        JOIN users u ON c.user_id = u.id
        WHERE c.short_code = ?
      `, [identifier], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    // If not found by short_code, try by slug (case-insensitive)
    if (!cardRow) {
      cardRow = await new Promise((resolve, reject) => {
        db.get(`
          SELECT c.data, c.short_code, c.slug, u.organisation_id
          FROM cards c
          JOIN users u ON c.user_id = u.id
          WHERE LOWER(c.slug) = ?
          LIMIT 1
        `, [identifierLower], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
    }

    if (!cardRow) {
      console.log('[Preview] Card not found:', identifier);
      return res.status(404).json({ error: 'Card not found' });
    }

    let cardData;
    try {
      cardData = JSON.parse(cardRow.data);
    } catch (e) {
      console.error('[Preview] Failed to parse card data:', e.message);
      return res.status(500).json({ error: 'Invalid card data' });
    }

    console.log('[Preview] Card data loaded for:', identifier);
    console.log('[Preview] Card avatar URL:', cardData.images?.avatar || '(none)');
    console.log('[Preview] Card name:', cardData.personal?.firstName, cardData.personal?.lastName);

    // Privacy Check: Return generic preview if card requires interaction or has obfuscation
    const privacy = cardData.privacy || {};
    if (privacy.requireInteraction || privacy.clientSideObfuscation) {
      console.log('[Preview] Privacy protection active for:', identifier);
      const genericImage = await generateGenericPreviewImage();
      if (!genericImage) {
        return res.status(500).json({ error: 'Failed to generate preview' });
      }

      res.set({
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=0, must-revalidate', // Always revalidate
        'Pragma': 'no-cache'
      });
      return res.send(genericImage);
    }

    // Generate preview image
    const themeColor = cardData.theme?.color || 'indigo';
    const previewBuffer = await generatePreviewImage(cardData, themeColor);

    if (!previewBuffer) {
      console.error('[Preview] Failed to generate preview image');
      return res.status(500).json({ error: 'Failed to generate preview' });
    }

    // Write to cache atomically
    if (cachedPath) {
      await writeToCacheAtomic(`preview_${identifier}.png`, previewBuffer);
    }

    // Return generated preview
    // Use must-revalidate to prevent Caddy from serving stale cached content
    res.set({
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=0, must-revalidate', // Always revalidate with ETag
      'Pragma': 'no-cache'
    });
    res.send(previewBuffer);
  } catch (err) {
    console.error('[Preview] Endpoint error:', err.message);
    next(err);
  }
});

// GET Org-scoped Card (Public endpoint - org slug + card slug)
// MUST come after /api/cards/short/:shortCode and /api/cards/:identifier/preview.png
router.get('/api/cards/:orgSlug/:cardSlug', cardReadLimiter, [
  param('orgSlug').trim().matches(/^[a-z0-9-]+$/).withMessage('Invalid org slug'),
  param('cardSlug').trim().matches(/^[a-z0-9-]+$/).withMessage('Invalid card slug')
], handleValidationErrors, (req, res, next) => {
  const orgSlug = req.params.orgSlug.toLowerCase();
  const cardSlug = req.params.cardSlug.toLowerCase();
  log(`[API] GET /api/cards/${orgSlug}/${cardSlug} - Request received`);

  // Lookup organization by slug
  db.get("SELECT id FROM organisations WHERE slug = ?", [orgSlug], (err, org) => {
    if (err) {
      console.error('[API] Database error fetching org:', err);
      return next(err);
    }
    if (!org) {
      log(`[API] Organization not found: ${orgSlug}`);
      return res.status(404).json({ error: "Card not found" }); // Generic 404, no info leakage
    }

    log(`[API] Organization found (id: ${org.id}), querying card...`);
    // Find card within that organization
    db.get(`
      SELECT c.data, c.short_code
      FROM cards c
      JOIN users u ON c.user_id = u.id
      WHERE c.slug = ? AND u.organisation_id = ?
      LIMIT 1
    `, [cardSlug, org.id], (err, row) => {
      if (err) {
        console.error('[API] Database error fetching card:', err);
        return next(err);
      }
      if (!row) {
        log(`[API] Card not found: ${cardSlug} in org ${orgSlug}`);
        return res.status(404).json({ error: "Card not found" });
      }
      try {
        const cardData = JSON.parse(row.data);
        // Include short_code in response for frontend QR generation
        cardData._shortCode = row.short_code;
        log(`[API] Card found, returning card data (has personal: ${!!cardData.personal})`);
        res.json(cardData);
      } catch (e) {
        console.error('[API] Error parsing card data:', e);
        next(e);
      }
    });
  });
});

// GET Single Card (Legacy endpoint - returns first match by slug, deprecated)
router.get('/api/cards/:slug', cardReadLimiter, [
  slugValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();
  // Public endpoint - get first card with this slug (multiple users can have same slug)
  // DEPRECATED: Use /api/cards/:orgSlug/:cardSlug or /api/cards/short/:shortCode instead
  db.get("SELECT data, short_code FROM cards WHERE slug = ? LIMIT 1", [slug], (err, row) => {
    if (err) return next(err);
    if (!row) return res.status(404).json({ error: "Card not found" });
    try {
      const cardData = JSON.parse(row.data);
      // Include short_code in response for frontend QR generation
      cardData._shortCode = row.short_code;
      res.setHeader('X-Deprecated', 'true');
      res.json(cardData);
    } catch (e) {
      next(e);
    }
  });
});

// GET Admin Card by Owner (Admin endpoint - fetch a specific user's card by userId and slug)
router.get('/api/admin/cards/:userId/:slug', apiLimiter, requireAuth, requireRole('owner'), [
  param('userId').isUUID().withMessage('Invalid userId'),
  slugValidation
], handleValidationErrors, (req, res, next) => {
  const targetUserId = req.params.userId;
  const slug = req.params.slug.toLowerCase();

  // Verify the target user belongs to the same organisation as the admin
  db.get(
    `SELECT u.id FROM users u
     WHERE u.id = ? AND u.organisation_id = (
       SELECT organisation_id FROM users WHERE id = ?
     )`,
    [targetUserId, req.user.id],
    (err, user) => {
      if (err) return next(err);
      if (!user) return res.status(404).json({ error: 'User not found in your organisation' });

      db.get(
        "SELECT data, short_code FROM cards WHERE slug = ? AND user_id = ?",
        [slug, targetUserId],
        (err, row) => {
          if (err) return next(err);
          if (!row) return res.status(404).json({ error: 'Card not found' });
          try {
            const cardData = JSON.parse(row.data);
            cardData._shortCode = row.short_code;
            res.json(cardData);
          } catch (e) {
            next(e);
          }
        }
      );
    }
  );
});

// SAVE/UPDATE Card
router.post('/api/cards/:slug', requireAuth, apiLimiter, csrfProtection, [
  slugValidation,
  ...cardDataValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();

  // Sanitize and validate the data structure
  const sanitizedData = {
    personal: {
      firstName: (req.body.personal?.firstName || '').trim().substring(0, 100),
      lastName: (req.body.personal?.lastName || '').trim().substring(0, 100),
      title: (req.body.personal?.title || '').trim().substring(0, 200),
      company: (req.body.personal?.company || '').trim().substring(0, 200),
      bio: (req.body.personal?.bio || '').trim().substring(0, 1000),
      location: (req.body.personal?.location || '').trim().substring(0, 200)
    },
    contact: {
      email: (req.body.contact?.email || '').trim(),
      phone: (req.body.contact?.phone || '').trim().substring(0, 50),
      website: (req.body.contact?.website || '').trim()
    },
    social: {
      linkedin: (req.body.social?.linkedin || '').trim(),
      twitter: (req.body.social?.twitter || '').trim(),
      instagram: (req.body.social?.instagram || '').trim(),
      github: (req.body.social?.github || '').trim()
    },
    theme: req.body.theme || { color: 'indigo', style: 'modern' },
    images: {
      avatar: (req.body.images?.avatar || '').trim().substring(0, 500),
      banner: (req.body.images?.banner || '').trim().substring(0, 500)
    },
    links: (req.body.links || []).map(link => ({
      id: link.id || Date.now(),
      title: (link.title || '').trim().substring(0, 200),
      url: (link.url || '').trim(),
      icon: link.icon || 'link'
    })).filter(link => link.url && validator.isURL(link.url, { protocols: ['http', 'https'] })),
    privacy: {
      requireInteraction: typeof req.body.privacy?.requireInteraction === 'boolean' ? req.body.privacy.requireInteraction : true,
      clientSideObfuscation: typeof req.body.privacy?.clientSideObfuscation === 'boolean' ? req.body.privacy.clientSideObfuscation : false,
      blockRobots: typeof req.body.privacy?.blockRobots === 'boolean' ? req.body.privacy.blockRobots : false
    }
  };

  // Ensure user is authenticated
  if (!req.user.id || !req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Determine target userId for card creation
  // Owners can create cards for other users in their organization
  // Members can only create cards for themselves

  // Helper function to proceed with card save using determined targetUserId
  const proceedWithCardSave = (finalTargetUserId) => {
    // Get organization settings to enforce policies
    getOrganizationSettings(req.user.organisationId, async (err, orgSettings) => {
      if (err) return next(err);

      // Enforce default_organisation - override user's company field
      if (orgSettings.default_organisation) {
        sanitizedData.personal.company = orgSettings.default_organisation;
      }

      // Enforce theme customisation policy
      if (!orgSettings.allow_theme_customisation) {
        // If theme customisation not allowed, validate theme colour is in org's theme_colours
        const requestedColor = sanitizedData.theme?.color;
        const allowedColors = orgSettings.theme_colors || [];
        const colorExists = allowedColors.some(c => c.name === requestedColor);

        if (!colorExists && requestedColor) {
          // Use first available color from org's palette, or default to 'indigo'
          sanitizedData.theme.color = allowedColors.length > 0 ? allowedColors[0].name : 'indigo';
        }
      }

      // Enforce image customisation policy
      if (!orgSettings.allow_image_customisation) {
        // Remove custom images if not allowed
        sanitizedData.images.avatar = '';
        sanitizedData.images.banner = '';
      }

      // Enforce links customisation policy
      if (!orgSettings.allow_links_customisation) {
        // Remove all custom links if not allowed
        sanitizedData.links = [];
      }

      // Enforce privacy customisation policy
      if (!orgSettings.allow_privacy_customisation) {
        // Reset to default privacy settings if customisation not allowed
        // Get existing card to preserve current privacy settings if they match defaults
        db.get("SELECT data FROM cards WHERE slug = ? AND user_id = ?", [slug, finalTargetUserId], async (err, existingCard) => {
          if (err) return next(err);

          if (existingCard) {
            try {
              const existingData = JSON.parse(existingCard.data);
              // Only reset if user tried to change privacy settings
              const privacyChanged =
                (req.body.privacy?.requireInteraction !== undefined &&
                 req.body.privacy.requireInteraction !== existingData.privacy?.requireInteraction) ||
                (req.body.privacy?.clientSideObfuscation !== undefined &&
                 req.body.privacy.clientSideObfuscation !== existingData.privacy?.clientSideObfuscation) ||
                (req.body.privacy?.blockRobots !== undefined &&
                 req.body.privacy.blockRobots !== existingData.privacy?.blockRobots);

              if (privacyChanged) {
                // Keep existing privacy settings (don't allow changes)
                sanitizedData.privacy = existingData.privacy || {
                  requireInteraction: true,
                  clientSideObfuscation: false,
                  blockRobots: false
                };
              } else {
                // No change attempted, use existing
                sanitizedData.privacy = existingData.privacy || sanitizedData.privacy;
              }
            } catch (e) {
              // If parsing fails, use defaults
              sanitizedData.privacy = {
                requireInteraction: true,
                clientSideObfuscation: false,
                blockRobots: false
              };
            }
          } else {
            // New card, use defaults
            sanitizedData.privacy = {
              requireInteraction: true,
              clientSideObfuscation: false,
              blockRobots: false
            };
          }

          try {
            const result = await upsertCard(slug, finalTargetUserId, sanitizedData);
            res.json({ success: true, ...result });
          } catch (err) {
            next(err);
          }
        });
      } else {
        // Privacy customisation allowed, save normally
        try {
          const result = await upsertCard(slug, finalTargetUserId, sanitizedData);
          res.json({ success: true, ...result });
        } catch (err) {
          next(err);
        }
      }
    });
  };

  // Determine target user and proceed
  if (req.body.userId && req.user.role === 'owner') {
    // Owner wants to create card for another user - verify they're in same organization
    db.get("SELECT id, organisation_id FROM users WHERE id = ?", [req.body.userId], (err, targetUser) => {
      if (err) return next(err);
      if (!targetUser) {
        return res.status(404).json({ error: 'Target user not found' });
      }
      if (targetUser.organisation_id !== req.user.organisationId) {
        return res.status(403).json({ error: 'Cannot create card for user outside your organization' });
      }
      // Valid target user, proceed with card creation
      proceedWithCardSave(req.body.userId);
    });
  } else {
    // Member provided userId - ignore it, they can only create for themselves
    // Or no userId provided - use current user
    proceedWithCardSave(req.user.id);
  }
});

// DELETE Card
router.delete('/api/cards/:slug', requireAuth, apiLimiter, csrfProtection, [
  slugValidation
], handleValidationErrors, async (req, res, next) => {
  const slug = req.params.slug.toLowerCase();
  // Ensure user is authenticated
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Owners may pass ?userId= to delete another user's card within their organisation
  const requestedUserId = req.query.userId || null;
  const isOwnerDeletingForUser =
    req.user.role === 'owner' && requestedUserId && requestedUserId !== req.user.id;

  const performDelete = (targetUserId) => {
    // First, fetch the card to get short_code for cache invalidation
    db.get("SELECT short_code FROM cards WHERE slug = ? AND user_id = ?", [slug, targetUserId], (err, card) => {
      if (err) return next(err);
      if (!card) {
        return res.status(404).json({ error: 'Card not found' });
      }

      const shortCode = card.short_code;

      // Now delete the card
      db.run("DELETE FROM cards WHERE slug = ? AND user_id = ?", [slug, targetUserId], async function(err) {
        if (err) return next(err);
        if (this.changes === 0) {
          return res.status(404).json({ error: 'Card not found' });
        }

        // Invalidate cache for both slug and short_code
        await invalidatePreviewCache(slug, shortCode);

        res.json({ success: true });
      });
    });
  };

  if (isOwnerDeletingForUser) {
    // Verify the target user belongs to the same organisation (use subquery to avoid stale JWT org value)
    db.get(
      "SELECT id FROM users WHERE id = ? AND organisation_id = (SELECT organisation_id FROM users WHERE id = ?)",
      [requestedUserId, req.user.id],
      (err, user) => {
        if (err) return next(err);
        if (!user) return res.status(404).json({ error: 'User not found in your organisation' });
        performDelete(requestedUserId);
      }
    );
  } else {
    performDelete(req.user.id);
  }
});

module.exports = router;
