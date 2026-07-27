const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const { randomUUID } = require('crypto');
const { db } = require('../db');
const { log } = require('./logger');
const { IS_DEMO_MODE, UPLOADS_DIR } = require('../config/env');
const { getDefaultThemeColors } = require('./themeColors');

// Shared mutable demo-mode state. `userId` is set once seeding completes, and
// middleware/auth.js reads it on every request in demo mode - it must stay a
// property on a shared object rather than a value re-exported by binding, so
// consumers always see the current value instead of the null captured at load.
const demoState = {
  isDemoMode: IS_DEMO_MODE,
  userId: null,
};

// Deletes all demo data (Demon Straight org/users/cards/settings), respecting
// foreign key constraints (child tables first, then parents). Shared by
// seedDemoData's cleanup phase and the hourly reset timer.
async function deleteDemoData() {
  // Delete all cards for demo users
  await new Promise((resolve) => {
    db.run(
      'DELETE FROM cards WHERE user_id IN (SELECT id FROM users WHERE email LIKE ?)',
      ['%@demonstraight.com'],
      (err) => {
        if (err) console.error('[DEMO MODE] Error deleting demo cards:', err.message);
        resolve();
      }
    );
  });

  // Delete all user settings for demo users
  await new Promise((resolve) => {
    db.run(
      'DELETE FROM user_settings WHERE user_id IN (SELECT id FROM users WHERE email LIKE ?)',
      ['%@demonstraight.com'],
      (err) => {
        if (err) console.error('[DEMO MODE] Error deleting user settings:', err.message);
        resolve();
      }
    );
  });

  // Delete all demo users by email domain (more reliable than org FK)
  await new Promise((resolve) => {
    db.run(
      'DELETE FROM users WHERE email LIKE ?',
      ['%@demonstraight.com'],
      (err) => {
        if (err) console.error('[DEMO MODE] Error deleting demo users:', err.message);
        resolve();
      }
    );
  });

  // Delete organisation settings for Demon Straight
  await new Promise((resolve) => {
    db.run(
      'DELETE FROM organisation_settings WHERE organisation_id IN (SELECT id FROM organisations WHERE slug = ?)',
      ['demon-straight'],
      (err) => {
        if (err) console.error('[DEMO MODE] Error deleting org settings:', err.message);
        resolve();
      }
    );
  });

  // Delete the demo organisation itself
  await new Promise((resolve) => {
    db.run(
      'DELETE FROM organisations WHERE slug = ?',
      ['demon-straight'],
      (err) => {
        if (err) console.error('[DEMO MODE] Error deleting org:', err.message);
        resolve();
      }
    );
  });
}

// Seed demo data for Demon Straight company
async function seedDemoData() {
  if (!IS_DEMO_MODE) return;

  try {
    log('[DEMO MODE] Seeding fresh demo data for Demon Straight...');

    // 0. Robustly delete all existing demo data (respecting foreign key constraints)
    await deleteDemoData();

    // 1. Define demo users
    const demoUsers = [
      { email: 'alex@demonstraight.com', role: 'owner' },
      { email: 'maria@demonstraight.com', role: 'member' },
      { email: 'james@demonstraight.com', role: 'member' },
      { email: 'sarah@demonstraight.com', role: 'member' },
      { email: 'david@demonstraight.com', role: 'member' },
      { email: 'emma@demonstraight.com', role: 'member' }
    ];

    // 2. Generate UUIDs for organisation and users (TEXT primary keys require explicit generation)
    const demoOrgId = randomUUID();
    const demoUserIds = demoUsers.map(() => randomUUID());

    // 3. Create demo organization
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)',
        [demoOrgId, 'Demon Straight', 'demon-straight'],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // 4. Create organization settings (individual inserts to avoid key conflicts)
    const settings = [
      { key: 'default_organisation', value: 'Demon Straight' },
      { key: 'theme_colors', value: JSON.stringify(getDefaultThemeColors()) },
      { key: 'theme_variant', value: 'swiish' },
      { key: 'allow_theme_customisation', value: '1' },
      { key: 'allow_image_customisation', value: '1' },
      { key: 'allow_links_customisation', value: '1' },
      { key: 'allow_privacy_customisation', value: '1' }
    ];

    for (const setting of settings) {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO organisation_settings (organisation_id, key, value) VALUES (?, ?, ?)',
          [demoOrgId, setting.key, setting.value],
          function(err) {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }

    // 5. Hash password
    const hashedPassword = await new Promise((resolve, reject) => {
      bcrypt.hash('demo123', 10, (err, hash) => {
        if (err) reject(err);
        else resolve(hash);
      });
    });

    // 5. Create users sequentially (using pre-generated UUIDs)
    for (let i = 0; i < demoUsers.length; i++) {
      const user = demoUsers[i];
      const userId = demoUserIds[i];
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO users (id, organisation_id, email, password_hash, role, email_verified)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [userId, demoOrgId, user.email, hashedPassword, user.role, 1],
          function(err) {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }

    // Store demo owner user ID for auth bypass in middleware
    demoState.userId = demoUserIds[0];
    log(`[DEMO MODE] Created 6 demo users with IDs: ${demoUserIds.join(',')}`);
    log(`[DEMO MODE] Demo owner user ID set to: ${demoState.userId}`);

    // 4. Create 6 demo cards
    const demoCards = [
      {
        userId: demoUserIds[0],
        slug: 'alex-ruler',
        shortCode: 'RULER01',
        data: {
          personal: { firstName: 'Alex', lastName: 'Ruler', title: 'Chief Straightness Officer & Founder', company: 'Demon Straight', bio: '30 years making things straight. Never once made a curve. Not even by accident.', location: 'London, UK' },
          contact: { email: 'alex@demonstraight.com', phone: '+44 20 7946 0958', website: 'https://demonstraight.demo' },
          social: { linkedin: 'https://linkedin.com/in/demo-alex-ruler', twitter: 'https://twitter.com/demo_ruler' },
          theme: { color: 'indigo', style: 'modern' },
          images: { avatar: '/demo/avatar-1.jpg', banner: '/demo/banner-1.jpg' },
          links: [
            { icon: 'globe', title: 'Company Website', url: 'https://demonstraight.demo', visible: true },
            { icon: 'download', title: 'Download Product Catalogue', url: 'https://demonstraight.demo/catalogue.pdf', visible: true },
            { icon: 'zap', title: 'View Latest Straightness Report', url: 'https://demonstraight.demo/reports/latest', visible: true },
            { icon: 'calendar', title: 'Book a Meeting', url: 'https://calendly.com/demo-alex', visible: true }
          ],
          privacy: { requireInteraction: false, clientSideObfuscation: false, blockRobots: false }
        }
      },
      {
        userId: demoUserIds[1],
        slug: 'maria-lines',
        shortCode: 'LINES02',
        data: {
          personal: { firstName: 'Maria', lastName: 'Lines', title: 'Director of Perfectly Straight Design', company: 'Demon Straight', bio: 'If it\'s not straight, I won\'t design it. My protractor has never measured an angle.', location: 'Manchester, UK' },
          contact: { email: 'maria@demonstraight.com', website: 'https://portfolio.demo.com/maria' },
          social: { linkedin: 'https://linkedin.com/in/demo-maria-lines' },
          theme: { color: 'purple', style: 'modern' },
          images: { avatar: '/demo/avatar-2.jpg', banner: '/demo/banner-1.jpg' },
          links: [
            { icon: 'eye', title: 'View Design Portfolio', url: 'https://portfolio.demo.com/maria', visible: true },
            { icon: 'book', title: 'Design Principles Guide', url: 'https://portfolio.demo.com/maria/principles', visible: true },
            { icon: 'image', title: 'Latest Design Work', url: 'https://portfolio.demo.com/maria/work', visible: true },
            { icon: 'mail', title: 'Enquire About Design Work', url: 'mailto:maria@demonstraight.com?subject=Design%20Inquiry', visible: true }
          ],
          privacy: { requireInteraction: true, clientSideObfuscation: false, blockRobots: false }
        }
      },
      {
        userId: demoUserIds[2],
        slug: 'james-level',
        shortCode: 'LEVEL03',
        data: {
          personal: { firstName: 'James', lastName: 'Level', title: 'Head of Straightness Solutions', company: 'Demon Straight', bio: 'Connecting businesses with our straight products. My sales pitch? It\'s perfectly straight.', location: 'Birmingham, UK' },
          contact: { email: 'james@demonstraight.com', phone: '+44 121 555 0123' },
          social: { linkedin: 'https://linkedin.com/in/demo-james-level' },
          theme: { color: 'blue', style: 'modern' },
          images: { avatar: '/demo/avatar-3.jpg', banner: '/demo/banner-1.jpg' },
          links: [
            { icon: 'play', title: 'Request a Product Demo', url: 'https://demonstraight.demo/demo-request', visible: true },
            { icon: 'trending-up', title: 'View Case Studies', url: 'https://demonstraight.demo/case-studies', visible: true },
            { icon: 'credit-card', title: 'Download Pricing', url: 'https://demonstraight.demo/pricing.pdf', visible: true },
            { icon: 'phone', title: 'Call Sales Team', url: 'tel:+441215550123', visible: true }
          ],
          privacy: { requireInteraction: false, clientSideObfuscation: false, blockRobots: false }
        }
      },
      {
        userId: demoUserIds[3],
        slug: 'sarah-edge',
        shortCode: 'EDGE04',
        data: {
          personal: { firstName: 'Sarah', lastName: 'Edge', title: 'Marketing & Straight Talk Lead', company: 'Demon Straight', bio: 'No curves in our messaging. Just straight facts about straight products.', location: 'Bristol, UK' },
          contact: { email: 'sarah@demonstraight.com' },
          social: { twitter: 'https://twitter.com/demo_sarah', linkedin: 'https://linkedin.com/in/demo-sarah-edge' },
          theme: { color: 'pink', style: 'modern' },
          images: { avatar: '/demo/avatar-4.jpg', banner: '/demo/banner-1.jpg' },
          links: [
            { icon: 'book', title: 'Read Our Blog', url: 'https://blog.demonstraight.demo', visible: true },
            { icon: 'send', title: 'Subscribe to Newsletter', url: 'https://demonstraight.demo/newsletter', visible: true },
            { icon: 'package', title: 'Download Media Kit', url: 'https://demonstraight.demo/media-kit.zip', visible: true },
            { icon: 'file', title: 'Press Releases', url: 'https://demonstraight.demo/press', visible: true }
          ],
          privacy: { requireInteraction: false, clientSideObfuscation: false, blockRobots: false }
        }
      },
      {
        userId: demoUserIds[4],
        slug: 'david-plumb',
        shortCode: 'PLUMB05',
        data: {
          personal: { firstName: 'David', lastName: 'Plumb', title: 'Senior Straightness Engineer', company: 'Demon Straight', bio: 'I write code as straight as our products. Zero tolerance for crooked semicolons.', location: 'Edinburgh, UK' },
          contact: { email: 'david@demonstraight.com' },
          social: { github: 'https://github.com/demo-david-plumb', linkedin: 'https://linkedin.com/in/demo-david-plumb' },
          theme: { color: 'emerald', style: 'modern' },
          images: { avatar: '/demo/avatar-5.jpg', banner: '/demo/banner-1.jpg' },
          links: [
            { icon: 'code', title: 'View Our Tech Stack', url: 'https://github.com/demon-straight-tech', visible: true },
            { icon: 'zap', title: 'Engineering Blog', url: 'https://tech.demonstraight.demo', visible: true },
            { icon: 'book', title: 'API Documentation', url: 'https://api.demonstraight.demo/docs', visible: true },
            { icon: 'package', title: 'Open Source Projects', url: 'https://github.com/demon-straight', visible: true }
          ],
          privacy: { requireInteraction: true, clientSideObfuscation: false, blockRobots: false }
        }
      },
      {
        userId: demoUserIds[5],
        slug: 'emma-align',
        shortCode: 'ALIGN06',
        data: {
          personal: { firstName: 'Emma', lastName: 'Align', title: 'Minimalist Designer', company: 'Demon Straight', bio: 'Less is more. Straight is best.', location: 'Leeds, UK' },
          contact: { email: 'emma@demonstraight.com' },
          social: { linkedin: 'https://linkedin.com/in/demo-emma-align' },
          theme: { color: 'slate', style: 'modern' },
          images: { avatar: '/demo/avatar-6.jpg' },
          links: [
            { icon: 'minus', title: 'View Minimal Design Work', url: 'https://portfolio.demo.com/emma/minimal', visible: true }
          ],
          privacy: { requireInteraction: false, clientSideObfuscation: false, blockRobots: false }
        }
      }
    ];

    // Create cards
    for (const card of demoCards) {
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO cards (user_id, slug, short_code, data) VALUES (?, ?, ?, ?)`,
          [card.userId, card.slug, card.shortCode, JSON.stringify(card.data)],
          function(err) {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }

    log('[DEMO MODE] Created 6 demo cards for Demon Straight');
  } catch (error) {
    console.error('[DEMO MODE] Error seeding demo data:', error);
    throw error;
  }
}

// Start hourly demo reset timer
function startDemoResetTimer() {
  if (!IS_DEMO_MODE) return;

  const resetInterval = 60 * 60 * 1000; // 1 hour in milliseconds

  setInterval(async () => {
    try {
      log('[DEMO MODE] Starting hourly reset - wiping demo data...');

      // Delete ONLY demo data (identified by @demonstraight.com emails)
      await deleteDemoData();

      // Delete all uploaded files except demo images (those are preserved for next cycle)
      // NOTE: this replicates the original `path.join(__dirname, UPLOADS_DIR)` double-join,
      // which since UPLOADS_DIR is already absolute resolves to a directory that never
      // exists - so this cleanup has always been a silent no-op. Preserved as-is since
      // fixing it would start actually deleting uploaded files, a behavior change out of
      // scope for this refactor.
      const uploadsDir = path.join(__dirname, UPLOADS_DIR);
      if (fs.existsSync(uploadsDir)) {
        const files = fs.readdirSync(uploadsDir);
        for (const file of files) {
          // Keep only demo images and user-uploaded files (if any)
          // In demo mode, assume all non-demo files are temporary user uploads
          if (!file.startsWith('demo-')) {
            try {
              fs.unlinkSync(path.join(uploadsDir, file));
            } catch (err) {
              log(`[DEMO MODE] Warning: Could not delete ${file}`, err.message);
            }
          }
        }
      }

      // Re-seed with fresh demo data
      await seedDemoData();

      log('[DEMO MODE] Reset complete. Fresh demo data restored.');
    } catch (error) {
      console.error('[DEMO MODE] Reset failed:', error);
      log('[DEMO MODE] Reset failed', error.message);
    }
  }, resetInterval);

  log(`[DEMO MODE] Hourly reset timer started (${resetInterval / 1000 / 60} minutes)`);
}

module.exports = {
  demoState,
  seedDemoData,
  startDemoResetTimer,
};
