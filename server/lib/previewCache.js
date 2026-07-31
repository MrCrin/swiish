const fs = require('fs');
const path = require('path');
const { PROJECT_ROOT } = require('../config/env');
const { resolveWithinDir } = require('./paths');
const { log } = require('./logger');

// --- 1.5 PREVIEW IMAGE CACHE SETUP ---
const PREVIEW_CACHE_DIR = path.join(PROJECT_ROOT, 'cache', 'previews');
const PREVIEW_CACHE_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const PREVIEW_CACHE_MAX_SIZE_MB = 100;

// Ensure cache directory exists
if (!fs.existsSync(PREVIEW_CACHE_DIR)) {
  fs.mkdirSync(PREVIEW_CACHE_DIR, { recursive: true });
  log('[Cache] Created preview cache directory');
}

// Clean up old cache files on startup (files older than 24 hours)
async function cleanOldCacheFiles() {
  try {
    const files = await fs.promises.readdir(PREVIEW_CACHE_DIR);
    let cleaned = 0;
    for (const file of files) {
      const filePath = path.join(PREVIEW_CACHE_DIR, file);
      const stat = await fs.promises.stat(filePath);
      if (Date.now() - stat.mtimeMs > PREVIEW_CACHE_MAX_AGE) {
        await fs.promises.unlink(filePath);
        cleaned++;
      }
    }
    if (cleaned > 0) {
      log(`[Cache] Cleaned ${cleaned} expired cache files`);
    }
  } catch (err) {
    log('[Cache] Error cleaning old cache files:', err.message);
  }
}

// Run cleanup on startup
cleanOldCacheFiles();

/**
 * Enforce cache size limit by removing oldest files when exceeding limit
 * Runs periodically to prevent unbounded cache growth
 */
async function enforceCacheSizeLimit() {
  try {
    const files = await fs.promises.readdir(PREVIEW_CACHE_DIR);
    let totalSize = 0;
    const fileStats = [];

    for (const file of files) {
      const filePath = path.join(PREVIEW_CACHE_DIR, file);
      const stat = await fs.promises.stat(filePath);
      totalSize += stat.size;
      fileStats.push({ file, filePath, mtime: stat.mtimeMs, size: stat.size });
    }

    const maxSizeBytes = PREVIEW_CACHE_MAX_SIZE_MB * 1024 * 1024;

    if (totalSize > maxSizeBytes) {
      fileStats.sort((a, b) => a.mtime - b.mtime);
      for (const f of fileStats) {
        await fs.promises.unlink(f.filePath);
        totalSize -= f.size;
        if (totalSize <= maxSizeBytes * 0.9) break; // Stop at 90% of limit
      }
      log(`[Cache] Enforced size limit, removed files. Current size: ${(totalSize / (1024 * 1024)).toFixed(2)} MB`);
    }
  } catch (err) {
    log('[Cache] Error enforcing size limit:', err.message);
  }
}

// Run size enforcement every hour
setInterval(enforceCacheSizeLimit, 60 * 60 * 1000);

/**
 * Atomic write to cache to prevent race conditions (write-then-rename pattern)
 */
async function writeToCacheAtomic(filename, buffer) {
  const tempPath = path.join(PREVIEW_CACHE_DIR, `${filename}.${Date.now()}.tmp`);
  const finalPath = path.join(PREVIEW_CACHE_DIR, filename);

  try {
    await fs.promises.writeFile(tempPath, buffer);
    await fs.promises.rename(tempPath, finalPath);
    console.log('[Cache] Written atomically:', filename);
  } catch (err) {
    // Try to clean up temp file
    try { await fs.promises.unlink(tempPath); } catch (e) {}
    console.error('[Cache] Atomic write failed:', err.message);
  }
}

/**
 * Validate and resolve cache path (Path Traversal Protection)
 */
function resolveCachePath(identifier) {
  // Allow alphanumeric and hyphens only
  if (!identifier || !/^[a-zA-Z0-9-]+$/.test(identifier)) return null;

  const filename = `preview_${identifier}.png`;
  return resolveWithinDir(PREVIEW_CACHE_DIR, path.join(PREVIEW_CACHE_DIR, filename));
}

/**
 * Invalidate preview cache for a card (by slug and short_code)
 */
async function invalidatePreviewCache(slug, shortCode) {
  const toDelete = [];

  // Add slug to cache invalidation
  if (slug) {
    const slugPath = resolveCachePath(slug);
    if (slugPath) toDelete.push(slugPath);
  }

  // Add short_code to cache invalidation
  if (shortCode) {
    const shortCodePath = resolveCachePath(shortCode);
    if (shortCodePath) toDelete.push(shortCodePath);
  }

  // Delete cache files in parallel
  for (const filePath of toDelete) {
    try {
      await fs.promises.unlink(filePath);
      console.log('[Cache] Invalidated:', path.basename(filePath));
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error('[Cache] Invalidation error:', err.message);
      }
    }
  }
}

module.exports = {
  PREVIEW_CACHE_DIR,
  cleanOldCacheFiles,
  enforceCacheSizeLimit,
  writeToCacheAtomic,
  resolveCachePath,
  invalidatePreviewCache,
};
