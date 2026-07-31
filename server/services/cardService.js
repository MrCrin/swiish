const { db } = require('../db');
const { ensureUniqueShortCode } = require('../lib/tokens');
const { invalidatePreviewCache } = require('../lib/previewCache');

// Upserts a card's JSON data, reusing an existing short_code or generating a
// new one. This is the exact "check short_code, then UPDATE or INSERT" logic
// that POST /api/cards/:slug previously duplicated once per branch of its
// allow_privacy_customisation check - the branches differ only in what they
// do to `sanitizedData` before saving, not in how the save itself happens.
function upsertCard(slug, targetUserId, sanitizedData) {
  return new Promise((resolve, reject) => {
    db.get("SELECT short_code FROM cards WHERE slug = ? AND user_id = ?", [slug, targetUserId], (err, existingCardWithCode) => {
      if (err) return reject(err);

      const existingShortCode = existingCardWithCode?.short_code;

      if (existingShortCode) {
        // Card exists with short code, just update data
        const jsonContent = JSON.stringify(sanitizedData);

        const query = `
          UPDATE cards
          SET data = ?, updated_at = CURRENT_TIMESTAMP
          WHERE slug = ? AND user_id = ?
        `;

        db.run(query, [jsonContent, slug, targetUserId], async function(err) {
          if (err) return reject(err);
          await invalidatePreviewCache(slug, existingShortCode);
          resolve({ slug, shortCode: existingShortCode });
        });
      } else {
        // Card doesn't exist or has no short code, generate one
        ensureUniqueShortCode(db, (err, shortCode) => {
          if (err) return reject(err);

          const jsonContent = JSON.stringify(sanitizedData);

          const query = `
            INSERT INTO cards (slug, user_id, short_code, data, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(slug, user_id) DO UPDATE SET
              data = excluded.data,
              short_code = COALESCE(cards.short_code, excluded.short_code),
              updated_at = CURRENT_TIMESTAMP
          `;

          db.run(query, [slug, targetUserId, shortCode, jsonContent], async function(err) {
            if (err) return reject(err);
            await invalidatePreviewCache(slug, shortCode);
            resolve({ slug, shortCode });
          });
        });
      }
    });
  });
}

module.exports = {
  upsertCard,
};
