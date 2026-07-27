const { db } = require('../db');
const { APP_URL } = require('../config/env');
const { escapeXml } = require('./previewImage');

// Helper function to inject meta tags for social media sharing
async function injectMetaTags(html, cardIdentifier, displayIdentifier) {
  // cardIdentifier is what we use for lookups
  // displayIdentifier is what we show in preview URLs (might include orgSlug for org-scoped)

  // Try to find card by short_code, slug, or org-scoped combination
  let cardRow;

  // Check if it's an org-scoped lookup (contains /)
  if (displayIdentifier.includes('/')) {
    const [orgSlug, cardSlug] = displayIdentifier.split('/');
    // Look up by organization + card slug
    cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code, c.updated_at
        FROM cards c
        JOIN users u ON c.user_id = u.id
        JOIN organisations o ON u.organisation_id = o.id
        WHERE LOWER(o.slug) = LOWER(?) AND LOWER(c.slug) = LOWER(?)
        LIMIT 1
      `, [orgSlug, cardSlug], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  } else {
    // Original logic for short code or slug lookup
    cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code, c.updated_at
        FROM cards c
        WHERE c.short_code = ? OR LOWER(c.slug) = LOWER(?)
        LIMIT 1
      `, [cardIdentifier, cardIdentifier], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  if (!cardRow) {
    return html; // Card not found, return unmodified HTML
  }

  try {
    const cardData = JSON.parse(cardRow.data);
    const privacy = cardData.privacy || {};

    // Privacy Leak Fix: "Block Robots" mode completely hides user identity
    if (privacy.blockRobots) {
      const robotsMeta = `
        <title>Private Card</title>
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex, nofollow">
      `;
      // Remove existing title tag to prevent duplicates
      html = html.replace(/<title>.*?<\/title>/i, '');
      // Insert before closing head tag
      return html.replace('</head>', robotsMeta + '</head>');
    }

    // Privacy Check: Don't expose preview for cards requiring interaction
    if (privacy.requireInteraction || privacy.clientSideObfuscation) {
      const privateMeta = `
        <title>Card Preview</title>
        <meta name="robots" content="noindex, follow">
      `;
      // Remove existing title tag to prevent duplicates
      html = html.replace(/<title>.*?<\/title>/i, '');
      return html.replace('</head>', privateMeta + '</head>');
    }

    // Safe to include preview - construct meta tags
    const firstName = escapeXml(cardData.personal?.firstName || '');
    const lastName = escapeXml(cardData.personal?.lastName || '');
    const title = escapeXml(cardData.personal?.title || '');
    const company = escapeXml(cardData.personal?.company || '');
    const fullName = `${firstName} ${lastName}`.trim();
    const description = title ? `${title} at ${company}` : company || 'Digital Business Card';

    // Construct preview image URL with cache-busting timestamp
    // Use short_code if available (globally unique), otherwise use the identifier
    const previewIdentifier = cardRow.short_code || cardIdentifier;
    // Add timestamp hash to force refresh when card is updated
    const updateTimestamp = cardRow.updated_at ? new Date(cardRow.updated_at).getTime() : Date.now();
    const previewUrl = `${APP_URL}/api/cards/${previewIdentifier}/preview.png?v=${updateTimestamp}`;

    // Construct canonical URL for og:url
    const cardUrl = `${APP_URL}/${displayIdentifier}`;

    const metaTags = `
        <title>${fullName} - Digital Business Card</title>
        <meta name="description" content="${description}">
        <meta property="og:url" content="${escapeXml(cardUrl)}">
        <meta property="og:title" content="${fullName}">
        <meta property="og:description" content="${description}">
        <meta property="og:image" content="${escapeXml(previewUrl)}">
        <meta property="og:image:width" content="1200">
        <meta property="og:image:height" content="630">
        <meta property="og:image:type" content="image/png">
        <meta property="og:type" content="profile">
        <meta name="twitter:card" content="summary_large_image">
        <meta name="twitter:title" content="${fullName}">
        <meta name="twitter:description" content="${description}">
        <meta name="twitter:image" content="${escapeXml(previewUrl)}">
        <meta name="robots" content="index, follow">
      `;

    // Remove existing title tag to prevent duplicates
    html = html.replace(/<title>.*?<\/title>/i, '');

    return html.replace('</head>', metaTags + '</head>');
  } catch (err) {
    console.error('[Meta Tags] Error parsing card data:', err.message);
    return html; // Return unmodified on error
  }
}

module.exports = {
  injectMetaTags,
};
