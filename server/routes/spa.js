const express = require('express');
const fs = require('fs');
const path = require('path');
const { BUILD_DIR } = require('../config/env');
const { publicReadLimiter } = require('../config/security');
const { injectMetaTags } = require('../lib/metaTags');

const router = express.Router();

// SPA Fallback - only for non-API and non-static routes
router.get('*', publicReadLimiter, async (req, res, next) => {
  // Don't serve index.html for static assets or API routes
  if (req.path.startsWith('/static/') || req.path.startsWith('/api/') || req.path.startsWith('/uploads/') || req.path.startsWith('/manifest/') || req.path.startsWith('/icons/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  try {
    // Read index.html from build directory
    const indexPath = path.join(BUILD_DIR, 'index.html');
    let html = await fs.promises.readFile(indexPath, 'utf8');

    // Try to detect card page and inject meta tags
    // Patterns:
    // 1. /{shortCode} - 7 alphanumeric characters (primary)
    // 2. /{orgSlug}/{cardSlug} - organization scoped
    // 3. /{slug} - legacy pattern (deprecated but still supported)

    const pathParts = req.path.slice(1).split('/').filter(p => p.length > 0);

    // Pattern 1: Short code (7 characters exactly)
    const isShortCode = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    if (isShortCode) {
      const shortCode = pathParts[0];
      html = await injectMetaTags(html, shortCode, shortCode);
    }
    // Pattern 2: Organization-scoped /{orgSlug}/{cardSlug}
    else if (pathParts.length === 2) {
      const [orgSlug, cardSlug] = pathParts;
      // Look up by org + card slug combination
      html = await injectMetaTags(html, cardSlug, `${orgSlug}/${cardSlug}`);
    }
    // Pattern 3: Legacy slug (anything that's not a short code and not org-scoped)
    else if (pathParts.length === 1) {
      const slug = pathParts[0];
      html = await injectMetaTags(html, slug, slug);
    }

    // Inject nonce into script tags (case-insensitive to catch all variants)
    html = html.replace(
      /<script(\s|>)/gi,
      `<script nonce="${res.locals.nonce}"$1`
    );

    // Replace %PUBLIC_URL% if needed (React build should already handle this, but be safe)
    html = html.replace(/%PUBLIC_URL%/g, '');

    // Set no-cache headers for index.html to ensure fresh content
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Content-Type': 'text/html; charset=utf-8'
    });

    res.send(html);
  } catch (err) {
    // If file doesn't exist or can't be read, return 404
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'Not found' });
    }
    next(err);
  }
});

module.exports = router;
