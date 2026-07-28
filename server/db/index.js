const path = require('path');
const util = require('util');
const sqlite3 = require('sqlite3').verbose();
const { DATA_DIR, IS_DEMO_MODE } = require('../config/env');

// Use separate database files for demo vs normal mode
const DB_FILENAME = IS_DEMO_MODE ? 'cards-demo.db' : 'cards.db';
const db = new sqlite3.Database(path.join(DATA_DIR, DB_FILENAME));

// CRITICAL: Enable foreign key constraints (required for CASCADE to work)
db.run("PRAGMA foreign_keys = ON", (err) => {
  if (err) {
    console.error('CRITICAL: Failed to enable foreign keys:', err);
    process.exit(1);
  }
  console.log('[DB] Foreign key constraints enabled');
});

if (IS_DEMO_MODE) {
  console.log(`[DB] Using demo database: ${DB_FILENAME}`);
} else {
  console.log(`[DB] Using normal database: ${DB_FILENAME}`);
}

// Promisified database methods for async/await error handling
const dbRun = util.promisify(db.run.bind(db));
const dbGet = util.promisify(db.get.bind(db));

module.exports = {
  db,
  dbRun,
  dbGet,
};
