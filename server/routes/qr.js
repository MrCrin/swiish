const express = require('express');
const { param, body } = require('express-validator');
const QRCode = require('qrcode');
const { db } = require('../db');
const { publicReadLimiter } = require('../config/security');
const { handleValidationErrors } = require('../middleware/validation');

const router = express.Router();

// QR Code Generation Endpoint
// GET: accepts slug or short code, generates QR with short code URL
router.get('/api/qr/:identifier', publicReadLimiter, [
  param('identifier').trim().matches(/^[a-zA-Z0-9-]+$/).withMessage('Invalid identifier')
], handleValidationErrors, async (req, res, next) => {
  try {
    const identifier = req.params.identifier;
    const baseUrl = req.protocol + '://' + req.get('host');

    // Check if it's a short code (exactly 7 alphanumeric chars) or slug
    const isShortCode = /^[a-zA-Z0-9]{7}$/.test(identifier);

    let cardUrl;
    if (isShortCode) {
      // Use short code directly
      cardUrl = `${baseUrl}/${identifier}`;

      const qrDataUrl = await QRCode.toDataURL(cardUrl, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        width: 200,
        margin: 1
      });

      res.json({ qrCode: qrDataUrl });
    } else {
      // Legacy: lookup by slug to get short code
      const slug = identifier.toLowerCase();
      db.get("SELECT short_code FROM cards WHERE slug = ? LIMIT 1", [slug], async (err, row) => {
        if (err) return next(err);
        if (!row || !row.short_code) {
          return res.status(404).json({ error: "Card not found" });
        }
        cardUrl = `${baseUrl}/${row.short_code}`;

        try {
          const qrDataUrl = await QRCode.toDataURL(cardUrl, {
            errorCorrectionLevel: 'M',
            type: 'image/png',
            width: 200,
            margin: 1
          });
          res.json({ qrCode: qrDataUrl });
        } catch (qrErr) {
          next(qrErr);
        }
      });
    }
  } catch (err) {
    next(err);
  }
});

// POST: optionally accept a rich payload to encode in the QR,
// falling back to the card short code URL if payload is missing/invalid.
router.post('/api/qr/:identifier', publicReadLimiter, [
  param('identifier').trim().matches(/^[a-zA-Z0-9-]+$/).withMessage('Invalid identifier'),
  body('payload')
    .optional()
    .isString()
    .isLength({ max: 5000 })
    .withMessage('payload must be a string up to 5000 characters')
], handleValidationErrors, async (req, res, next) => {
  try {
    const identifier = req.params.identifier;
    const baseUrl = req.protocol + '://' + req.get('host');

    // Check if it's a short code (exactly 7 alphanumeric chars) or slug
    const isShortCode = /^[a-zA-Z0-9]{7}$/.test(identifier);

    let cardUrl;
    if (isShortCode) {
      // Use short code directly
      cardUrl = `${baseUrl}/${identifier}`;
    } else {
      // Legacy: lookup by slug to get short code
      const slug = identifier.toLowerCase();
      db.get("SELECT short_code FROM cards WHERE slug = ? LIMIT 1", [slug], async (err, row) => {
        if (err) return next(err);
        if (!row || !row.short_code) {
          return res.status(404).json({ error: "Card not found" });
        }
        cardUrl = `${baseUrl}/${row.short_code}`;

        let qrContent = cardUrl;
        if (typeof req.body?.payload === 'string' && req.body.payload.trim()) {
          // Use the provided payload as-is; it may itself be JSON
          qrContent = req.body.payload.trim();
        }

        try {
          const qrDataUrl = await QRCode.toDataURL(qrContent, {
            errorCorrectionLevel: 'M',
            type: 'image/png',
            width: 200,
            margin: 1
          });
          res.json({ qrCode: qrDataUrl });
        } catch (qrErr) {
          next(qrErr);
        }
      });
      return;
    }

    let qrContent = cardUrl;
    if (typeof req.body?.payload === 'string' && req.body.payload.trim()) {
      // Use the provided payload as-is; it may itself be JSON
      qrContent = req.body.payload.trim();
    }

    const qrDataUrl = await QRCode.toDataURL(qrContent, {
      errorCorrectionLevel: 'M',
      type: 'image/png',
      width: 200,
      margin: 1
    });

    res.json({ qrCode: qrDataUrl });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
