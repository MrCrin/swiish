const express = require('express');
const fs = require('fs');
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const { uploadLimiter, csrfProtection } = require('../config/security');
const { upload, ALLOWED_MIME_TYPES } = require('../lib/uploadConfig');
const { validateFilePath } = require('../lib/paths');
const { log } = require('../lib/logger');

const router = express.Router();

// Image Upload Endpoint
router.post('/api/upload', requireAuth, uploadLimiter, csrfProtection, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Validate file type by reading actual file content
    const filePath = req.file.path;
    // Dynamic import for ESM-only file-type package
    const { fileTypeFromFile } = await import('file-type');
    const fileType = await fileTypeFromFile(filePath);

    if (!fileType || !ALLOWED_MIME_TYPES.includes(fileType.mime)) {
      // Delete the uploaded file if it's not valid
      try {
        const safePath = validateFilePath(filePath);
        await fs.promises.unlink(safePath);
      } catch (unlinkErr) {
        // Log but don't fail the request if cleanup fails
        log('Failed to delete invalid file:', unlinkErr.message);
      }
      return res.status(400).json({ error: 'Invalid file type. Only images are allowed.' });
    }

    // Verify extension matches MIME type
    const ext = path.extname(req.file.filename).toLowerCase();
    const expectedExt = {
      'image/jpeg': '.jpg',
      'image/png': '.png',
      'image/webp': '.webp',
      'image/gif': '.gif'
    };

    if (expectedExt[fileType.mime] !== ext) {
      try {
        const safePath = validateFilePath(filePath);
        await fs.promises.unlink(safePath);
      } catch (unlinkErr) {
        // Log but don't fail the request if cleanup fails
        log('Failed to delete invalid file:', unlinkErr.message);
      }
      return res.status(400).json({ error: 'File extension does not match file type' });
    }

    // Return the public URL
    res.json({ url: `/uploads/${req.file.filename}` });
  } catch (err) {
    // Clean up file if error occurred
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        const safePath = validateFilePath(req.file.path);
        await fs.promises.unlink(safePath);
      } catch (unlinkErr) {
        // Log but don't fail the request if cleanup fails
        log('Failed to delete file on error:', unlinkErr.message);
      }
    }
    next(err);
  }
});

module.exports = router;
