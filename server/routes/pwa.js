const express = require('express');
const fs = require('fs');
const path = require('path');
const { db } = require('../db');
const { PUBLIC_DIR } = require('../config/env');
const { publicReadLimiter } = require('../config/security');
const { handleValidationErrors, identifierValidation } = require('../middleware/validation');
const { getThemeColorHex } = require('../lib/themeColors');

const router = express.Router();

// Dynamic per-card manifest endpoint
router.get('/manifest/:slug.json', publicReadLimiter, [
  identifierValidation
], handleValidationErrors, async (req, res, next) => {
  // Get original identifier (before lowercasing) to preserve short code case
  const originalIdentifier = req.params.slug;
  // Check if it's a short code (exactly 7 alphanumeric chars) - case sensitive
  const isShortCode = /^[a-zA-Z0-9]{7}$/.test(originalIdentifier);
  // Use original for short codes, lowercase for slugs
  const identifier = isShortCode ? originalIdentifier : originalIdentifier.toLowerCase();


  // Load base manifest from disk (fallback if needed)
  let baseManifest = {
    short_name: 'Swiish',
    name: 'Swiish',
    start_url: '.',
    display: 'standalone',
    background_color: '#020617',
    theme_color: '#020617',
    icons: [
      { src: '/swiish-logo.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }
    ]
  };

  try {
    const manifestPath = path.join(PUBLIC_DIR, 'manifest.json');
    try {
      const raw = await fs.promises.readFile(manifestPath, 'utf8');
      const parsed = JSON.parse(raw);
      baseManifest = {
        short_name: parsed.short_name || baseManifest.short_name,
        name: parsed.name || baseManifest.name,
        start_url: parsed.start_url || baseManifest.start_url,
        display: parsed.display || baseManifest.display,
        background_color: parsed.background_color || baseManifest.background_color,
        theme_color: parsed.theme_color || baseManifest.theme_color,
        icons: Array.isArray(parsed.icons) && parsed.icons.length > 0 ? parsed.icons : baseManifest.icons
      };
    } catch (readErr) {
      // File doesn't exist or can't be read - use default manifest
      // This is fine, we have a fallback
    }
  } catch (err) {
    console.error('Failed to read base manifest:', err);
  }

  // Look up card by short_code or slug - need both data and slug for icon generation
  const query = isShortCode
    ? "SELECT data, slug FROM cards WHERE short_code = ?"
    : "SELECT data, slug FROM cards WHERE slug = ?";

  db.get(query, [identifier], (err, row) => {
    if (err) return next(err);

    if (!row) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Use the actual card slug for icon generation (not the short code or org slug)
    const cardSlug = row.slug;

    let cardName = 'Swiish Card';
    if (row && row.data) {
      try {
        const parsed = JSON.parse(row.data);
        const first = (parsed.personal?.firstName || '').trim();
        const last = (parsed.personal?.lastName || '').trim();
        const full = `${first} ${last}`.trim();
        cardName = full || parsed.personal?.company || cardName;
      } catch (e) {
        // fallback to default cardName
      }
    }

    // Use the identifier from URL for start_url (preserves short code or org-scoped routes)
    const startUrl = `/${identifier}/`;
    const manifest = {
      ...baseManifest,
      name: cardName,
      short_name: cardName.length > 20 ? cardName.slice(0, 20) : cardName,
      start_url: startUrl,
      scope: startUrl,
      icons: [
        { src: `/icons/${cardSlug}.svg`, sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
        { src: `/icons/${cardSlug}.svg`, sizes: '192x192', type: 'image/svg+xml' },
        { src: `/icons/${cardSlug}.svg`, sizes: '512x512', type: 'image/svg+xml' }
      ]
    };

    res.json(manifest);
  });
});

// Dynamic themed SVG icon endpoint
router.get('/icons/:slug.svg', publicReadLimiter, [
  identifierValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();

  // Get card data AND the user's organization_id in one query
  db.get(`
    SELECT c.data, u.organisation_id
    FROM cards c
    JOIN users u ON c.user_id = u.id
    WHERE c.slug = ?
  `, [slug], (err, row) => {
    if (err) return next(err);

    if (!row) {
      return res.status(404).type('image/svg+xml').send(`<svg xmlns="http://www.w3.org/2000/svg"><text>Card not found</text></svg>`);
    }

    let themeColor = 'indigo';
    if (row.data) {
      try {
        const parsed = JSON.parse(row.data);
        themeColor = parsed.theme?.color || 'indigo';
      } catch (e) {
        // fallback to indigo
      }
    }

    // Query settings for theme_colors from the card's ACTUAL organization
    const orgId = row.organisation_id;

    // Handle case where organisation_id might be null
    if (!orgId) {
      const fillColor = getThemeColorHex(themeColor);
      const svgPath = "M356.35,66.77h-59.65v-27.16c0-21.79-17.83-39.62-39.62-39.62H6.6C2.96,0,0,2.96,0,6.6v130.94c0,21.79,17.83,39.62,39.62,39.62h35.71c3.08,0,5.57-2.49,5.57-5.57v-78.41c0-14.59,11.82-26.41,26.41-26.41h16.52c3.65,0,6.6,2.96,6.6,6.6v8.49c0,3.65-2.96,6.6-6.6,6.6h-9.13c-3.65,0-6.6,2.96-6.6,6.6v76.53c0,3.08,2.49,5.57,5.57,5.57h143.42c21.79,0,39.62-17.83,39.62-39.62v-44.37h59.65c7.26,0,13.21,5.94,13.21,13.21v127.63c0,7.26-5.94,13.21-13.21,13.21H121.01c-7.26,0-13.21-5.94-13.21-13.21v-6.83c0-3.65-2.96-6.6-6.6-6.6h-13.21c-3.65,0-6.6,2.96-6.6,6.6v6.83c0,21.79,17.83,39.62,39.62,39.62h235.34c21.79,0,39.62-17.83,39.62-39.62v-127.63c0-21.79-17.83-39.62-39.62-39.62Z";
      const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg id="Layer_2" data-name="Layer 2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 395.96 273.63">
  <g id="Layer_1-2" data-name="Layer 1">
    <path fill="${fillColor}" d="${svgPath}"/>
  </g>
</svg>`;
      return res.type('image/svg+xml').send(svg);
    }

    db.get(`
      SELECT os.value
      FROM organisation_settings os
      WHERE os.organisation_id = ? AND os.key = ?
    `, [orgId, 'theme_colors'], (settingsErr, settingsRow) => {
      let fillColor = '#4f46e5'; // default to indigo

      if (!settingsErr && settingsRow && settingsRow.value) {
        try {
          const theme_colors = JSON.parse(settingsRow.value);
          const colorEntry = theme_colors.find(c => c.name === themeColor);

          if (colorEntry) {
            // Use textStyle (hex value) or hexBase, fall back to colorMap
            fillColor = colorEntry.textStyle || colorEntry.hexBase || getThemeColorHex(themeColor);
          } else {
            // Color not found in settings, use colorMap
            fillColor = getThemeColorHex(themeColor);
          }
        } catch (e) {
          // Parse error, fall back to colorMap
          fillColor = getThemeColorHex(themeColor);
        }
      } else {
        // No settings found, use colorMap
        fillColor = getThemeColorHex(themeColor);
      }


      // SVG path from Swiish_Logo_Device.svg (extracted from the actual file)
      // viewBox: 0 0 395.96 273.63
      const svgPath = "M356.35,66.77h-59.65v-27.16c0-21.79-17.83-39.62-39.62-39.62H6.6C2.96,0,0,2.96,0,6.6v130.94c0,21.79,17.83,39.62,39.62,39.62h35.71c3.08,0,5.57-2.49,5.57-5.57v-78.41c0-14.59,11.82-26.41,26.41-26.41h16.52c3.65,0,6.6,2.96,6.6,6.6v8.49c0,3.65-2.96,6.6-6.6,6.6h-9.13c-3.65,0-6.6,2.96-6.6,6.6v76.53c0,3.08,2.49,5.57,5.57,5.57h143.42c21.79,0,39.62-17.83,39.62-39.62v-44.37h59.65c7.26,0,13.21,5.94,13.21,13.21v127.63c0,7.26-5.94,13.21-13.21,13.21H121.01c-7.26,0-13.21-5.94-13.21-13.21v-6.83c0-3.65-2.96-6.6-6.6-6.6h-13.21c-3.65,0-6.6,2.96-6.6,6.6v6.83c0,21.79,17.83,39.62,39.62,39.62h235.34c21.79,0,39.62-17.83,39.62-39.62v-127.63c0-21.79-17.83-39.62-39.62-39.62Z";

      const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg id="Layer_2" data-name="Layer 2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 395.96 273.63">
  <g id="Layer_1-2" data-name="Layer 1">
    <path fill="${fillColor}" d="${svgPath}"/>
  </g>
</svg>`;

      res.type('image/svg+xml').send(svg);
    });
  });
});

module.exports = router;
