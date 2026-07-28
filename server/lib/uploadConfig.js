const path = require('path');
const multer = require('multer');
const { randomUUID } = require('crypto');
const { UPLOADS_DIR, MAX_FILE_SIZE } = require('../config/env');

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    // Use UUID for filename to prevent path traversal and collisions
    const ext = path.extname(file.originalname).toLowerCase();
    // Sanitize extension - only allow whitelisted extensions
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Invalid file type'));
    }
    cb(null, randomUUID() + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    // Basic MIME type check (will be validated again after upload)
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Invalid file extension'));
    }
    cb(null, true);
  }
});

module.exports = {
  ALLOWED_MIME_TYPES,
  ALLOWED_EXTENSIONS,
  upload,
};
