const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const { NODE_ENV, ALLOWED_ORIGINS } = require('./env');

// Security headers - configure CSP with connect-src for GitHub API
const cspDirectives = {
  defaultSrc: ["'self'"],
  imgSrc: ["'self'", "data:", "https:"],
  styleSrc: ["'self'", "'unsafe-inline'"], // Keep for CSS (less critical)
  fontSrc: ["'self'", "data:"],
  // Allow debug logging endpoint in development only (for development debugging)
  // Also allow GitHub API for version checking
  connectSrc: NODE_ENV === 'development'
    ? ["'self'", "http://127.0.0.1:7243", "http://localhost:7243", "https://api.github.com"]
    : ["'self'", "https://api.github.com"]
};

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.) in development
    if (!origin && NODE_ENV === 'development') {
      return callback(null, true);
    }
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
};

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 uploads per hour
  message: 'Too many upload attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Additional rate limiters for different endpoint types
const publicReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // More lenient for public read operations
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const cardReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Moderate limit for card reads
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// CSRF protection (skip for GET requests and public endpoints)
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

module.exports = {
  cspDirectives,
  corsOptions,
  loginLimiter,
  apiLimiter,
  uploadLimiter,
  publicReadLimiter,
  cardReadLimiter,
  csrfProtection,
};
