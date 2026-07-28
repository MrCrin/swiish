const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const { UPLOADS_DIR, PUBLIC_DIR } = require('../config/env');
const { resolveWithinDir } = require('./paths');
const { getThemeColorHex } = require('./themeColors');

// --- PHASE 2: SECURE IMAGE GENERATION MODULE ---

/**
 * PROPER XML ESCAPING (Fixes V2 Vulnerability)
 * Escapes special characters for safe use in SVG/XML contexts
 */
const escapeXml = (str) => {
  if (!str) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
};

/**
 * Secure Avatar Fetching with Path Validation
 * Prevents path traversal attacks by validating all paths
 */
async function fetchAvatarImage(avatarUrl) {
  try {
    if (!avatarUrl) {
      console.log('[Preview] No avatar URL provided');
      return null;
    }

    // 1. Local Uploads with Path Validation
    if (avatarUrl.startsWith('/uploads/')) {
      const filename = path.basename(avatarUrl);
      const safePath = resolveWithinDir(UPLOADS_DIR, path.join(UPLOADS_DIR, filename));

      console.log('[Preview] Attempting to load upload:', { avatarUrl, filename, safePath });

      if (!safePath) {
        console.warn('[Preview] Invalid upload path attempted:', avatarUrl);
        return null;
      }
      const buffer = await fs.promises.readFile(safePath);
      console.log('[Preview] Avatar loaded successfully:', filename, 'size:', buffer.length, 'bytes');
      return buffer;
    }

    // 2. Demo Images with Path Validation (Fixes V2 Vulnerability)
    if (avatarUrl.startsWith('/demo/')) {
      const filename = path.basename(avatarUrl);
      const demoDir = path.join(PUBLIC_DIR, 'demo');
      const safePath = resolveWithinDir(demoDir, path.join(demoDir, filename));

      console.log('[Preview] Attempting to load demo:', { avatarUrl, filename, safePath });

      if (!safePath) {
        console.warn('[Preview] Invalid demo path attempted:', avatarUrl);
        return null;
      }
      const buffer = await fs.promises.readFile(safePath);
      console.log('[Preview] Demo avatar loaded successfully:', filename, 'size:', buffer.length, 'bytes');
      return buffer;
    }

    // 3. External URLs (Whitelisted) - with timeout
    if (avatarUrl.startsWith('http')) {
      // For now, we don't support external URLs in preview generation
      // This could be added with proper whitelist and timeout handling
      console.warn('[Preview] External URLs not supported in preview generation:', avatarUrl);
      return null;
    }

    console.warn('[Preview] Avatar URL format not recognized:', avatarUrl);
    return null;
  } catch (err) {
    console.error('[Preview] Error fetching avatar:', err.message, 'for URL:', avatarUrl);
    return null;
  }
}

/**
 * Generate a generic "Protected" preview image (for privacy-protected cards)
 */
async function generateGenericPreviewImage() {
  const width = 1200;
  const height = 630;

  try {
    const svg = `
      <svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <rect width="${width}" height="${height}" fill="#f3f4f6"/>
        <rect width="${width}" height="${height}" fill="url(#grad)" opacity="0.1"/>
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#4f46e5;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#7c3aed;stop-opacity:1" />
          </linearGradient>
        </defs>
        <text x="600" y="315" font-family="Arial, sans-serif" font-size="48" font-weight="bold" text-anchor="middle" fill="#6b7280">
          Card Preview
        </text>
        <text x="600" y="370" font-family="Arial, sans-serif" font-size="24" text-anchor="middle" fill="#9ca3af">
          This card is private
        </text>
      </svg>
    `;

    return await sharp(Buffer.from(svg))
      .png()
      .toBuffer();
  } catch (err) {
    console.error('[Preview] Error generating generic preview:', err.message);
    return null;
  }
}

/**
 * Generate social media preview image (1200x630 PNG)
 * Includes card name, title, avatar, and theme color
 * Uses image compositing instead of SVG embedding for better avatar rendering
 */
async function generatePreviewImage(cardData, themeColor) {
  try {
    const firstName = cardData.personal?.firstName || '';
    const lastName = cardData.personal?.lastName || '';
    const title = cardData.personal?.title || '';
    const avatarUrl = cardData.images?.avatar || '';

    // Escape content for safe XML inclusion
    const escapedName = escapeXml(`${firstName} ${lastName}`.trim());
    const escapedTitle = escapeXml(title);
    const escapedCompany = escapeXml(cardData.personal?.company || '');
    const colorHex = getThemeColorHex(themeColor);

    const width = 1200;
    const height = 630;

    // Create base SVG without avatar (avatar will be composited separately)
    const svg = `
      <svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:${colorHex};stop-opacity:1" />
            <stop offset="100%" style="stop-color:${colorHex};stop-opacity:0.7" />
          </linearGradient>
        </defs>

        <!-- Background -->
        <rect width="${width}" height="${height}" fill="#ffffff"/>

        <!-- Gradient overlay on left side -->
        <rect x="0" y="0" width="400" height="${height}" fill="url(#grad)"/>

        <!-- Name -->
        <text x="500" y="260" font-family="Atkinson Hyperlegible" font-size="56" font-weight="bold" fill="#3d3d3d">
          ${escapedName}
        </text>

        <!-- Title -->
        <text x="500" y="330" font-family="Atkinson Hyperlegible" font-size="28" fill="#6b7280">
          ${escapedTitle}
        </text>

        <!-- Accent line (same x positioning as text) -->
        <rect x="500" y="358" width="100" height="6" fill="${colorHex}"/>

        <!-- Company name -->
        <text x="500" y="408" font-family="Atkinson Hyperlegible" font-size="28" fill="#6b7280">
          ${escapedCompany}
        </text>
      </svg>
    `;

    // Start with base image
    let image = await sharp(Buffer.from(svg)).png().toBuffer();
    let imageSharp = sharp(image);

    // Add avatar if available
    if (avatarUrl) {
      try {
        const avatarBuffer = await fetchAvatarImage(avatarUrl);
        if (avatarBuffer) {
          console.log('[Preview] Processing avatar image...');

          // 25% bigger: 180 * 1.25 = 225
          const avatarSize = 250;

          // Calculate position to center avatar in left half (400px wide)
          const avatarLeft = Math.round((400 - avatarSize) / 2);
          const avatarTop = Math.round((height - avatarSize) / 2);

          // Resize and create circular avatar using SVG mask
          // Create a circle SVG that will be used as a mask (white circle on black background = visible circle)
          const circleMaskSvg = `
            <svg width="${avatarSize}" height="${avatarSize}" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <mask id="circleMask">
                  <rect width="${avatarSize}" height="${avatarSize}" fill="black"/>
                  <circle cx="${avatarSize/2}" cy="${avatarSize/2}" r="${avatarSize/2}" fill="white"/>
                </mask>
              </defs>
              <rect width="${avatarSize}" height="${avatarSize}" mask="url(#circleMask)" fill="white"/>
            </svg>
          `;

          // Resize avatar and apply circular crop
          const resizedAvatar = await sharp(avatarBuffer)
            .resize(avatarSize, avatarSize, { fit: 'cover' })
            .composite([
              {
                input: Buffer.from(circleMaskSvg),
                blend: 'dest-in'
              }
            ])
            .png()
            .toBuffer();

          console.log(`[Preview] Compositing circular avatar at position (${avatarLeft}, ${avatarTop})...`);

          // Composite avatar onto main image (no border)
          imageSharp = imageSharp.composite([
            { input: resizedAvatar, left: avatarLeft, top: avatarTop }
          ]);

          console.log('[Preview] Avatar composited successfully');
        }
      } catch (err) {
        console.warn('[Preview] Could not composite avatar:', err.message, err.stack);
      }
    }

    return await imageSharp.png().toBuffer();
  } catch (err) {
    console.error('[Preview] Error generating preview image:', err.message);
    return null;
  }
}

module.exports = {
  escapeXml,
  fetchAvatarImage,
  generateGenericPreviewImage,
  generatePreviewImage,
};
