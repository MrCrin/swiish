const { db } = require('../db');
const { getDefaultThemeColors } = require('../lib/themeColors');

// Full organisation settings (all keys, all defaults) - used by the admin
// settings route and by the card-save flow to resolve org policy toggles.
const getOrganizationSettings = (organisationId, callback) => {
  db.all("SELECT key, value FROM organisation_settings WHERE organisation_id = ?", [organisationId], (err, rows) => {
    if (err) return callback(err, null);

    const settings = {};
    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings[row.key] = JSON.parse(row.value);
        } else if (row.key.startsWith('allow_')) {
          settings[row.key] = row.value === 'true';
        } else {
          settings[row.key] = row.value;
        }
      } catch (e) {
        console.error(`Error parsing setting ${row.key}:`, e);
      }
    });

    // Ensure defaults
    if (!settings.default_organisation) settings.default_organisation = 'My Organisation';
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) settings.theme_variant = 'swiish';
    if (settings.allow_theme_customisation === undefined) settings.allow_theme_customisation = true;
    if (settings.allow_image_customisation === undefined) settings.allow_image_customisation = true;
    if (settings.allow_links_customisation === undefined) settings.allow_links_customisation = true;
    if (settings.allow_privacy_customisation === undefined) settings.allow_privacy_customisation = true;

    callback(null, settings);
  });
};

// Public subset of settings (theme_colors, theme_variant, default_organisation only),
// looked up by organisation slug. Deliberately kept separate from
// getOrganizationSettings: it queries a different key set and has different
// defaults (no allow_* toggles), so merging it would change the public
// response shape.
const getPublicSettingsByOrgSlug = (orgSlug, callback) => {
  db.all(`
    SELECT os.key, os.value
    FROM organisation_settings os
    JOIN organisations o ON os.organisation_id = o.id
    WHERE o.slug = ? AND os.key IN ('theme_colors', 'theme_variant', 'default_organisation')
  `, [orgSlug], (err, rows) => {
    if (err) return callback(err, null);

    const settings = {};

    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings.theme_colors = JSON.parse(row.value);
        } else if (row.key === 'theme_variant') {
          settings.theme_variant = row.value;
        } else if (row.key === 'default_organisation') {
          settings.default_organisation = row.value;
        }
      } catch (e) {
        console.error(`Error parsing setting ${row.key}:`, e);
      }
    });

    // Ensure defaults
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) {
      settings.theme_variant = 'swiish';
    }
    if (!settings.default_organisation) {
      settings.default_organisation = 'My Organisation';
    }

    callback(null, settings);
  });
};

module.exports = {
  getOrganizationSettings,
  getPublicSettingsByOrgSlug,
};
