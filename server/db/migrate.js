const { execSync } = require('child_process');
const { db } = require('./index');
const { log } = require('../lib/logger');
const { ensureUniqueShortCode } = require('../lib/tokens');
const { PROJECT_ROOT, IS_DEMO_MODE } = require('../config/env');
const { seedDemoData, startDemoResetTimer } = require('../lib/demoMode');

// Data migration: Backfill short codes for existing cards that don't have them
function backfillShortCodes() {
  db.all("SELECT slug, user_id FROM cards WHERE short_code IS NULL OR short_code = ''", [], (err, rows) => {
    if (err) {
      console.error('Error checking for cards without short codes:', err);
      return;
    }
    if (rows && rows.length > 0) {
      log(`Found ${rows.length} cards without short codes, generating...`);
      let processed = 0;
      rows.forEach(row => {
        ensureUniqueShortCode(db, (err, shortCode) => {
          if (err) {
            console.error('Error generating short code:', err);
            return;
          }
          db.run("UPDATE cards SET short_code = ? WHERE slug = ? AND user_id = ?",
            [shortCode, row.slug, row.user_id],
            (err) => {
              if (err) {
                console.error('Error updating card with short code:', err);
              } else {
                processed++;
                if (processed === rows.length) {
                  log(`Successfully backfilled ${processed} cards with short codes`);
                }
              }
            }
          );
        });
      });
    }
  });
}

// Run database migrations before starting the server
async function runMigrations() {
  try {
    console.log('Running database migrations...');
    // Use demo environment for demo mode, otherwise use dev
    const migrateEnv = IS_DEMO_MODE ? 'demo' : 'dev';
    execSync(`npx db-migrate up --env ${migrateEnv}`, {
      stdio: 'inherit',
      cwd: PROJECT_ROOT
    });
    console.log('Database migrations completed successfully');

    // Wait for database to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Verify tables exist before seeding
    const tablesExist = await new Promise((resolve) => {
      db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, tables) => {
        if (err) {
          console.error('Error checking tables:', err.message);
          resolve(false);
        } else {
          const tableNames = tables.map(t => t.name);
          console.log('Tables found:', tableNames);
          resolve(tableNames.includes('organisations') && tableNames.includes('users'));
        }
      });
    });

    if (!tablesExist) {
      console.error('ERROR: Database tables were not created by migrations');
      process.exit(1);
    }

    // Seed demo data if demo mode is enabled
    if (IS_DEMO_MODE) {
      await seedDemoData();
      startDemoResetTimer();
    }

    // Run data migration after schema migrations and seeding
    try {
      backfillShortCodes();
    } catch (err) {
      // Ignore errors if no cards exist yet
      if (err.code !== 'SQLITE_ERROR') {
        throw err;
      }
    }
  } catch (error) {
    console.error('Migration failed:', error.message);
    process.exit(1);
  }
}

module.exports = {
  runMigrations,
  backfillShortCodes,
};
