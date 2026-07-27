const { body, param, validationResult } = require('express-validator');
const validator = require('validator');
const { NODE_ENV } = require('../config/env');

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Return the first error message in a user-friendly format
    const firstError = errors.array()[0];
    let errorMessage = firstError.msg;

    // Make error messages more specific
    if (firstError.param === 'password' && firstError.msg.includes('length')) {
      errorMessage = 'Password must be at least 8 characters long';
    } else if (firstError.param === 'email') {
      errorMessage = 'Please enter a valid email address';
    } else if (firstError.param === 'role') {
      errorMessage = 'Role must be either "owner" or "member"';
    }

    return res.status(400).json({
      error: errorMessage,
      details: NODE_ENV === 'development' ? errors.array() : undefined
    });
  }
  next();
};

// Validation schemas
const slugValidation = param('slug')
  .trim()
  .matches(/^[a-z0-9-]+$/)
  .withMessage('Slug must contain only lowercase letters, numbers, and hyphens')
  .isLength({ min: 1, max: 50 })
  .withMessage('Slug must be between 1 and 50 characters');

// More permissive validation for manifest/icon endpoints (allows uppercase for short codes)
const identifierValidation = param('slug')
  .trim()
  .matches(/^[a-zA-Z0-9-]+$/)
  .withMessage('Identifier must contain only letters, numbers, and hyphens')
  .isLength({ min: 1, max: 50 })
  .withMessage('Identifier must be between 1 and 50 characters');

const cardDataValidation = [
  body('personal.firstName').optional().trim().isLength({ max: 100 }).withMessage('First name too long'),
  body('personal.lastName').optional().trim().isLength({ max: 100 }).withMessage('Last name too long'),
  body('personal.title').optional().trim().isLength({ max: 200 }).withMessage('Title too long'),
  body('personal.company').optional().trim().isLength({ max: 200 }).withMessage('Company name too long'),
  body('personal.bio').optional().trim().isLength({ max: 1000 }).withMessage('Bio too long'),
  body('personal.location').optional().trim().isLength({ max: 200 }).withMessage('Location too long'),
  body('contact.email').optional().trim().custom((value) => {
    if (value && !validator.isEmail(value)) {
      throw new Error('Invalid email format');
    }
    return true;
  }),
  body('contact.phone').optional().trim().isLength({ max: 50 }).withMessage('Phone too long'),
  body('contact.website').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid website URL');
    }
    return true;
  }),
  body('social.linkedin').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid LinkedIn URL');
    }
    return true;
  }),
  body('social.twitter').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid Twitter URL');
    }
    return true;
  }),
  body('social.instagram').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid Instagram URL');
    }
    return true;
  }),
  body('social.github').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid GitHub URL');
    }
    return true;
  }),
  body('links').optional().isArray().withMessage('Links must be an array'),
  body('links.*.title').optional().trim().isLength({ max: 200 }).withMessage('Link title too long'),
  body('links.*.url').optional().trim().custom((value) => {
    if (value && !validator.isURL(value, { protocols: ['http', 'https'] })) {
      throw new Error('Invalid link URL');
    }
    return true;
  }),
  body('images.avatar').optional().trim().isLength({ max: 500 }).withMessage('Avatar URL too long'),
  body('images.banner').optional().trim().isLength({ max: 500 }).withMessage('Banner URL too long'),
  body('privacy.requireInteraction').optional().isBoolean().withMessage('requireInteraction must be a boolean'),
  body('privacy.clientSideObfuscation').optional().isBoolean().withMessage('clientSideObfuscation must be a boolean'),
  body('privacy.blockRobots').optional().isBoolean().withMessage('blockRobots must be a boolean')
];

module.exports = {
  handleValidationErrors,
  slugValidation,
  identifierValidation,
  cardDataValidation,
};
