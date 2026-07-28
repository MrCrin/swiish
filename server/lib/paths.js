const path = require('path');
const { UPLOADS_DIR } = require('../config/env');

/**
 * Generic path-traversal guard: resolves `candidatePath` to an absolute path
 * and returns it only if it lives inside `baseDir`, otherwise returns null.
 * This is the shared primitive behind the cache-path and avatar-path checks.
 */
function resolveWithinDir(baseDir, candidatePath) {
  const resolvedPath = path.resolve(candidatePath);
  const resolvedBase = path.resolve(baseDir);

  if (!resolvedPath.startsWith(resolvedBase)) {
    return null;
  }

  return resolvedPath;
}

// Path validation helper to prevent path traversal attacks (uploads-scoped)
function validateFilePath(filePath) {
  if (!filePath) {
    throw new Error('File path is required');
  }

  const resolvedPath = resolveWithinDir(UPLOADS_DIR, filePath);

  if (!resolvedPath) {
    throw new Error('Invalid file path: path traversal detected');
  }

  return resolvedPath;
}

module.exports = {
  resolveWithinDir,
  validateFilePath,
};
