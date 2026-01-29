require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, param, validationResult } = require('express-validator');
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
// file-type v19 is ESM-only, will use dynamic import when needed
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const util = require('util');
const { execSync } = require('child_process');
const sharp = require('sharp');

const app = express();
const PORT = process.env.PORT || 3000;

// Short code configuration
const SHORT_CODE_LENGTH = 7;
const SHORT_CODE_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

// Logging configuration
const MAX_LOG_LINES = 1000;

// Simple logging system
const logFile = path.join(__dirname, 'server.log');
const maxLogLines = MAX_LOG_LINES; // Keep last MAX_LOG_LINES lines
let logLines = [];

// Helper function to log with timestamp
function log(message, data = null) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}${data ? ' ' + JSON.stringify(data, null, 2) : ''}`;
  // Only log to console in development
  if (NODE_ENV === 'development') {
    console.log(logEntry);
  }
  logLines.push(logEntry);
  // Keep only last maxLogLines
  if (logLines.length > maxLogLines) {
    logLines = logLines.slice(-maxLogLines);
  }
  // Async file write (fire-and-forget)
  fs.promises.appendFile(logFile, logEntry + '\n', 'utf8').catch(err => {
    // Silently fail - don't break app if log file write fails
    console.error('Failed to write to log file:', err.message);
  });
}

// Trust proxy for rate limiting behind reverse proxy/load balancer
app.set('trust proxy', 1);

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error(`ERROR: Missing required environment variables: ${missingEnvVars.join(', ')}`);
  console.error('Please set these in your .env file or environment.');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'http://localhost:8095'];
const NODE_ENV = process.env.NODE_ENV || 'development';

// Email configuration
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASSWORD = process.env.SMTP_PASSWORD;
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@localhost';
const APP_URL = process.env.APP_URL || (() => {
  if (NODE_ENV === 'production') {
    console.error('ERROR: APP_URL must be set in production environment');
    console.error('Please set APP_URL in your .env file with your actual domain (e.g., https://yourdomain.com)');
    process.exit(1);
  }
  return 'http://localhost:3000';
})();

// Demo Mode configuration
const IS_DEMO_MODE = process.env.DEMO_MODE === 'true';
let DEMO_USER_ID = null; // Will be set after seeding

// Warn if demo mode is enabled
if (IS_DEMO_MODE) {
  console.log('');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('🚀 [DEMO MODE ENABLED] 🚀');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('Company: Demon Straight - Making Things Straight Since 1994');
  console.log('Admin Account: alex@demonstraight.com / demo123');
  console.log('Reset Interval: Every 60 minutes');
  console.log('────────────────────────────────────────────────────────────────');
  console.log('⚠️  DEMO MODE SHOULD ONLY BE ENABLED FOR TESTING/DEMO INSTANCES');
  console.log('⚠️  DO NOT USE IN PRODUCTION - ALL DATA RESETS HOURLY');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('');
}

// Create email transporter (only if SMTP is configured)
let emailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASSWORD) {
  emailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASSWORD
    }
  });
} else if (NODE_ENV === 'development') {
  // In development, log emails to console instead
  emailTransporter = {
    sendMail: async (options) => {
      console.log('=== EMAIL (Development Mode) ===');
      console.log('To:', options.to);
      console.log('Subject:', options.subject);
      console.log('Text:', options.text);
      console.log('HTML:', options.html);
      console.log('===============================');
      return { messageId: 'dev-' + Date.now() };
    }
  };
} else if (NODE_ENV === 'production') {
  // Warn in production if SMTP is not configured
  console.warn('WARNING: SMTP not configured. Email features (invitations, password resets) will not work.');
  console.warn('Configure SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in your .env file to enable email features.');
}

// --- 1. SETUP DIRECTORIES ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Path validation helper to prevent path traversal attacks
function validateFilePath(filePath) {
  if (!filePath) {
    throw new Error('File path is required');
  }
  // Resolve to absolute path
  const resolvedPath = path.resolve(filePath);
  const resolvedUploadsDir = path.resolve(UPLOADS_DIR);
  
  // Ensure the file is within uploads directory
  if (!resolvedPath.startsWith(resolvedUploadsDir)) {
    throw new Error('Invalid file path: path traversal detected');
  }
  
  return resolvedPath;
}

// --- 1.5 PREVIEW IMAGE CACHE SETUP ---
const PREVIEW_CACHE_DIR = path.join(__dirname, 'cache', 'previews');
const PREVIEW_CACHE_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const PREVIEW_CACHE_MAX_SIZE_MB = 100;

// Ensure cache directory exists
if (!fs.existsSync(PREVIEW_CACHE_DIR)) {
  fs.mkdirSync(PREVIEW_CACHE_DIR, { recursive: true });
  console.log('[Cache] Preview cache directory created:', PREVIEW_CACHE_DIR);
}

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
  const resolvedPath = path.resolve(PREVIEW_CACHE_DIR, filename);
  const resolvedCacheDir = path.resolve(PREVIEW_CACHE_DIR);

  if (!resolvedPath.startsWith(resolvedCacheDir)) return null;

  return resolvedPath;
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

// --- 2. SETUP DATABASE (SQLite) ---
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

// Helper function to log audit events
async function logAudit(eventType, entityType, entityId, entityData, performedBy, organisationId) {
  const auditId = require('crypto').randomUUID();
  return new Promise((resolve, reject) => {
    db.run(
      "INSERT INTO audit_log (id, event_type, entity_type, entity_id, entity_data, performed_by, organisation_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [auditId, eventType, entityType, entityId, JSON.stringify(entityData), performedBy, organisationId],
      (err) => {
        if (err) {
          console.error('[AUDIT] Failed to log event:', err);
          reject(err);
        } else {
          resolve(auditId);
        }
      }
    );
  });
}

// Helper function to map theme color name to hex (for SVG icon theming)
const getThemeColorHex = (colorName) => {
  if (!colorName || typeof colorName !== 'string') {
    return '#4f46e5'; // default to indigo
  }

  const normalizedColorName = colorName.toLowerCase().trim();
  const colorMap = {
    indigo: '#4f46e5',
    blue: '#2563eb',
    rose: '#e11d48',
    emerald: '#059669',
    slate: '#475569',
    purple: '#7c3aed',
    cyan: '#0891b2',
    teal: '#0d9488',
    orange: '#ea580c',
    pink: '#db2777',
    violet: '#7c3aed',
    fuchsia: '#c026d3',
    amber: '#d97706',
    lime: '#65a30d',
    green: '#16a34a',
    yellow: '#ca8a04',
    red: '#dc2626'
  };

  return colorMap[normalizedColorName] || '#4f46e5';
};

// Helper function to get default theme colours (hex-only format)
const getDefaultThemeColors = () => [
  { 
    name: "indigo", 
    colorType: "standard", 
    baseColor: "indigo", 
    hexBase: "#4f46e5", 
    hexSecondary: "#7c3aed",
    gradientStyle: "linear-gradient(135deg, #4f46e5, #7c3aed)",
    buttonStyle: "#4f46e5",
    linkStyle: "#4f46e5",
    textStyle: "#4f46e5"
  },
  { 
    name: "blue", 
    colorType: "standard", 
    baseColor: "blue", 
    hexBase: "#2563eb", 
    hexSecondary: "#0891b2",
    gradientStyle: "linear-gradient(135deg, #2563eb, #0891b2)",
    buttonStyle: "#2563eb",
    linkStyle: "#2563eb",
    textStyle: "#2563eb"
  },
  { 
    name: "rose", 
    colorType: "standard", 
    baseColor: "rose", 
    hexBase: "#e11d48", 
    hexSecondary: "#ea580c",
    gradientStyle: "linear-gradient(135deg, #e11d48, #ea580c)",
    buttonStyle: "#e11d48",
    linkStyle: "#e11d48",
    textStyle: "#e11d48"
  },
  { 
    name: "emerald", 
    colorType: "standard", 
    baseColor: "emerald", 
    hexBase: "#059669", 
    hexSecondary: "#0d9488",
    gradientStyle: "linear-gradient(135deg, #059669, #0d9488)",
    buttonStyle: "#059669",
    linkStyle: "#059669",
    textStyle: "#059669"
  },
  { 
    name: "slate", 
    colorType: "standard", 
    baseColor: "slate", 
    hexBase: "#475569", 
    hexSecondary: "#475569",
    gradientStyle: "linear-gradient(135deg, #475569, #475569)",
    buttonStyle: "#475569",
    linkStyle: "#475569",
    textStyle: "#475569"
  }
];

// Database migrations are handled by db-migrate (see migrations/ directory)
// Run migrations before starting the server (see startup code below)

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

// --- 3. SETUP UPLOADS (Multer) ---
const { randomUUID } = require('crypto');
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024; // 5MB default

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

// --- MIDDLEWARE ---

// Generate nonce middleware (must be BEFORE helmet for CSP)
app.use((req, res, next) => {
  // Generate cryptographically random nonce for each request
  const nonce = require('crypto').randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  next();
});

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

app.use((req, res, next) => {
  // Set scriptSrc with nonce for this request
  const scriptSrc = [
    "'self'",
    `'nonce-${res.locals.nonce}'`
  ];
  
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        ...cspDirectives,
        scriptSrc: scriptSrc
      }
    },
    crossOriginEmbedderPolicy: false
  })(req, res, next);
});

// CORS configuration
app.use(cors({
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
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

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

// HTTPS enforcement (if not behind reverse proxy)
if (NODE_ENV === 'production') {
  app.use((req, res, next) => {
    // Check if request is already secure (via reverse proxy)
    if (req.headers['x-forwarded-proto'] === 'https' || req.secure) {
      return next();
    }
    // Only redirect if explicitly configured
    if (process.env.FORCE_HTTPS === 'true') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// Serve the React App Build
app.use(express.static(path.join(__dirname, 'build'), {
  maxAge: '1d', // Cache static assets for 1 day
  etag: true,
  lastModified: true,
  index: false // Don't automatically serve index.html - let SPA fallback handle it
}));
// Serve Uploaded Images publicly
app.use('/uploads', express.static(UPLOADS_DIR));

// --- AUTHENTICATION MIDDLEWARE ---

// JWT Authentication middleware
const requireAuth = (req, res, next) => {
  // Demo mode: auto-authenticate as demo owner user
  if (IS_DEMO_MODE && DEMO_USER_ID) {
    // Get demo user from database (using callback API since sqlite3 is async)
    db.get(
      'SELECT id, role, organisation_id FROM users WHERE id = ?',
      [DEMO_USER_ID],
      (err, row) => {
        if (err || !row) {
          return res.status(401).json({ error: 'Demo user not found' });
        }
        req.user = {
          id: row.id,
          organisationId: row.organisation_id,
          role: row.role
        };
        next();
      }
    );
    return;
  }

  // Normal authentication flow
  const token = req.cookies.authToken || (req.headers.authorization && req.headers.authorization.replace('Bearer ', ''));

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Support both old format (admin: true) and new format (user_id, organisation_id, role)
    if (decoded.user_id) {
      req.user = {
        id: decoded.user_id,
        organisationId: decoded.organisation_id || null,
        role: decoded.role || 'member'
      };
    } else if (decoded.admin) {
      // Backward compatibility: if old JWT format, treat as admin
      // This allows old tokens to still work during transition
      req.user = {
        id: null,
        organisationId: null,
        role: 'admin'
      };
    } else {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

// Role-based access control middleware
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    
    next();
  };
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  // Don't leak error details in production
  if (NODE_ENV === 'production') {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
  
  // In development, show more details
  res.status(err.status || 500).json({ 
    error: err.message || 'Internal server error',
    stack: err.stack 
  });
};

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

// --- PHASE 2: SECURE IMAGE GENERATION MODULE ---

/**
 * PROPER XML ESCAPING (Fixes V2 Vulnerability)
 * Escapes special characters for safe use in SVG/XML contexts
 */
const escapeXml = (str) => {
  if (!str) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
};

/**
 * Secure Avatar Fetching with Path Validation
 * Prevents path traversal attacks by validating all paths
 */
async function fetchAvatarImage(avatarUrl) {
  try {
    if (!avatarUrl) {
      console.log('[Preview] No avatar URL provided');
      return null;
    }

    // 1. Local Uploads with Path Validation
    if (avatarUrl.startsWith('/uploads/')) {
      const filename = path.basename(avatarUrl);
      const safePath = path.resolve(UPLOADS_DIR, filename);
      const resolvedUploads = path.resolve(UPLOADS_DIR);

      console.log('[Preview] Attempting to load upload:', { avatarUrl, filename, safePath });

      if (!safePath.startsWith(resolvedUploads)) {
        console.warn('[Preview] Invalid upload path attempted:', avatarUrl);
        return null;
      }
      const buffer = await fs.promises.readFile(safePath);
      console.log('[Preview] Avatar loaded successfully:', filename, 'size:', buffer.length, 'bytes');
      return buffer;
    }

    // 2. Demo Images with Path Validation (Fixes V2 Vulnerability)
    if (avatarUrl.startsWith('/demo/')) {
      const filename = path.basename(avatarUrl);
      const safePath = path.resolve(__dirname, 'public', 'demo', filename);
      const resolvedDemo = path.resolve(__dirname, 'public', 'demo');

      console.log('[Preview] Attempting to load demo:', { avatarUrl, filename, safePath });

      if (!safePath.startsWith(resolvedDemo)) {
        console.warn('[Preview] Invalid demo path attempted:', avatarUrl);
        return null;
      }
      const buffer = await fs.promises.readFile(safePath);
      console.log('[Preview] Demo avatar loaded successfully:', filename, 'size:', buffer.length, 'bytes');
      return buffer;
    }

    // 3. External URLs (Whitelisted) - with timeout
    if (avatarUrl.startsWith('http')) {
      // For now, we don't support external URLs in preview generation
      // This could be added with proper whitelist and timeout handling
      console.warn('[Preview] External URLs not supported in preview generation:', avatarUrl);
      return null;
    }

    console.warn('[Preview] Avatar URL format not recognized:', avatarUrl);
    return null;
  } catch (err) {
    console.error('[Preview] Error fetching avatar:', err.message, 'for URL:', avatarUrl);
    return null;
  }
}

/**
 * Generate a generic "Protected" preview image (for privacy-protected cards)
 */
async function generateGenericPreviewImage() {
  const width = 1200;
  const height = 630;

  try {
    const svg = `
      <svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <rect width="${width}" height="${height}" fill="#f3f4f6"/>
        <rect width="${width}" height="${height}" fill="url(#grad)" opacity="0.1"/>
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#4f46e5;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#7c3aed;stop-opacity:1" />
          </linearGradient>
        </defs>
        <text x="600" y="315" font-family="Arial, sans-serif" font-size="48" font-weight="bold" text-anchor="middle" fill="#6b7280">
          Card Preview
        </text>
        <text x="600" y="370" font-family="Arial, sans-serif" font-size="24" text-anchor="middle" fill="#9ca3af">
          This card is private
        </text>
      </svg>
    `;

    return await sharp(Buffer.from(svg))
      .png()
      .toBuffer();
  } catch (err) {
    console.error('[Preview] Error generating generic preview:', err.message);
    return null;
  }
}

/**
 * Generate social media preview image (1200x630 PNG)
 * Includes card name, title, avatar, and theme color
 * Uses image compositing instead of SVG embedding for better avatar rendering
 */
async function generatePreviewImage(cardData, themeColor) {
  try {
    const firstName = cardData.personal?.firstName || '';
    const lastName = cardData.personal?.lastName || '';
    const title = cardData.personal?.title || '';
    const avatarUrl = cardData.images?.avatar || '';

    // Escape content for safe XML inclusion
    const escapedName = escapeXml(`${firstName} ${lastName}`.trim());
    const escapedTitle = escapeXml(title);
    const colorHex = getThemeColorHex(themeColor);

    const width = 1200;
    const height = 630;

    // Create base SVG without avatar (avatar will be composited separately)
    const svg = `
      <svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:${colorHex};stop-opacity:1" />
            <stop offset="100%" style="stop-color:${colorHex};stop-opacity:0.8" />
          </linearGradient>
        </defs>

        <!-- Background -->
        <rect width="${width}" height="${height}" fill="#ffffff"/>

        <!-- Gradient overlay on left side -->
        <rect x="0" y="0" width="400" height="${height}" fill="url(#grad)"/>

        <!-- Name -->
        <text x="500" y="280" font-family="Arial, sans-serif" font-size="56" font-weight="bold" fill="#1f2937">
          ${escapedName}
        </text>

        <!-- Title -->
        <text x="500" y="350" font-family="Arial, sans-serif" font-size="28" fill="#6b7280">
          ${escapedTitle}
        </text>

        <!-- Accent line -->
        <rect x="500" y="370" width="100" height="4" fill="${colorHex}"/>
      </svg>
    `;

    // Start with base image
    let image = await sharp(Buffer.from(svg)).png().toBuffer();
    let imageSharp = sharp(image);

    // Add avatar if available
    if (avatarUrl) {
      try {
        const avatarBuffer = await fetchAvatarImage(avatarUrl);
        if (avatarBuffer) {
          console.log('[Preview] Creating circular avatar mask...');

          // Resize and create circular avatar
          const avatarSize = 180;
          const avatarCircle = await sharp(avatarBuffer)
            .resize(avatarSize, avatarSize, { fit: 'cover' })
            .composite([{
              input: Buffer.from(`
                <svg width="${avatarSize}" height="${avatarSize}">
                  <circle cx="${avatarSize/2}" cy="${avatarSize/2}" r="${avatarSize/2}" fill="white"/>
                </svg>
              `),
              blend: 'dest-in'
            }])
            .png()
            .toBuffer();

          console.log('[Preview] Compositing avatar onto preview image...');

          // Composite avatar onto main image at position (120, 330) - centered vertically
          imageSharp = imageSharp.composite([
            { input: avatarCircle, left: 120, top: 330 }
          ]);

          // Add a subtle border circle around avatar
          const borderSvg = `
            <svg width="180" height="180">
              <circle cx="90" cy="90" r="88" fill="none" stroke="${colorHex}" stroke-width="3" opacity="0.4"/>
            </svg>
          `;
          imageSharp = imageSharp.composite([
            { input: Buffer.from(borderSvg), left: 120, top: 330 }
          ]);

          console.log('[Preview] Avatar composited successfully');
        }
      } catch (err) {
        console.warn('[Preview] Could not composite avatar:', err.message);
      }
    }

    return await imageSharp.png().toBuffer();
  } catch (err) {
    console.error('[Preview] Error generating preview image:', err.message);
    return null;
  }
}

// --- API ROUTES ---

// CSRF token endpoint (public, before auth)
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Setup endpoints (public, only work if no users exist)
app.get('/api/setup/status', apiLimiter, (req, res, next) => {
  // In demo mode, setup is always considered complete
  if (IS_DEMO_MODE) {
    return res.json({
      setupComplete: true,
      userCount: 6, // 6 demo users
      demoMode: true
    });
  }

  db.get("SELECT COUNT(*) as count FROM users", [], (err, row) => {
    if (err) return next(err);
    res.json({
      setupComplete: row.count > 0,
      userCount: row.count,
      demoMode: false
    });
  });
});

// Demo mode status endpoint (public)
app.get('/api/demo/status', apiLimiter, (req, res) => {
  res.json({
    demoMode: IS_DEMO_MODE,
    resetInterval: 60, // minutes
    company: IS_DEMO_MODE ? 'Demon Straight' : null,
    credentials: IS_DEMO_MODE ? { email: 'alex@demonstraight.com', password: 'demo123' } : null
  });
});

app.post('/api/setup/initialize', apiLimiter, csrfProtection, [
  body('organisationName').trim().isLength({ min: 1, max: 200 }).withMessage('Organisation name is required and must be less than 200 characters'),
  body('adminEmail').isEmail({ allow_display_name: false, require_tld: false }).withMessage('Valid email required'),
  body('adminPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  // Only allow setup if no users exist
  db.get("SELECT COUNT(*) as count FROM users", [], async (err, row) => {
    if (err) return next(err);
    if (row.count > 0) {
      return res.status(403).json({ error: 'Setup already completed' });
    }
    
    const { organisationName, adminEmail, adminPassword } = req.body;
    
    // Generate organisation slug from name
    // Fix ReDoS: use separate replace calls instead of alternation in single regex
    const orgSlug = organisationName.toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+/, '')  // Remove leading dashes (no alternation)
      .replace(/-+$/, '')  // Remove trailing dashes (no alternation)
      || 'organisation';
    
    // Find available slug (shouldn't be needed on fresh install, but be safe)
    const findAvailableSlug = (slug, counter = 0) => {
      const finalSlug = counter === 0 ? slug : `${orgSlug}-${counter}`;
      db.get("SELECT id FROM organisations WHERE slug = ?", [finalSlug], (err, existingOrg) => {
        if (err) return next(err);
        if (existingOrg) {
          findAvailableSlug(slug, counter + 1);
        } else {
          createOrgAndUser(finalSlug);
        }
      });
    };
    
    findAvailableSlug(orgSlug);
    
    async function createOrgAndUser(slug) {
      const orgId = require('crypto').randomUUID();
      const userId = require('crypto').randomUUID();
      
      try {
        const passwordHash = await bcrypt.hash(adminPassword, 10);
        
        // Create organisation
        db.run(`
          INSERT INTO organisations (id, name, slug, subscription_tier)
          VALUES (?, ?, ?, ?)
        `, [orgId, organisationName, slug, 'individual'], (err) => {
          if (err) return next(err);
          
          // Create admin user
          db.run(`
            INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified)
            VALUES (?, ?, ?, ?, ?, ?)
          `, [userId, adminEmail.toLowerCase(), passwordHash, orgId, 'owner', 0], async (err) => {
            if (err) return next(err);
            
            // Initialize default organisation settings
            const defaultColors = getDefaultThemeColors();
            try {
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'default_organisation', organisationName]);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'theme_colors', JSON.stringify(defaultColors)]);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_theme_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_image_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_links_customisation', 'true']);
              await dbRun("INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", [orgId, 'allow_privacy_customisation', 'true']);
            } catch (err) {
              return next(err);
            }
            
            // Generate JWT token
            const token = jwt.sign(
              {
                user_id: userId,
                organisation_id: orgId,
                role: 'owner'
              },
              JWT_SECRET,
              { expiresIn: JWT_EXPIRES_IN }
            );
            
            // Set httpOnly cookie
            res.cookie('authToken', token, {
              httpOnly: true,
              secure: NODE_ENV === 'production',
              sameSite: 'strict',
              maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });
            
            res.json({ success: true, userId, email: adminEmail.toLowerCase(), role: 'owner' });
          });
        });
      } catch (err) {
        return next(err);
      }
    }
  });
});

// Login
app.post('/api/login', loginLimiter, [
  body('email').custom((value) => {
    // Allow localhost emails for development
    if (value && (validator.isEmail(value) || /^[^\s@]+@localhost(\.[^\s@]+)?$/.test(value))) {
      return true;
    }
    throw new Error('Valid email required');
  }),
  body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Look up user by email
    db.get("SELECT id, email, password_hash, organisation_id, role FROM users WHERE email = ?", [email.toLowerCase()], async (err, user) => {
      if (err) {
        return next(err);
      }
      
      // If no user found, return error
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      
      // Generate JWT token
      const token = jwt.sign(
        {
          user_id: user.id,
          organisation_id: user.organisation_id,
          role: user.role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );
      
      // Set httpOnly cookie
      res.cookie('authToken', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      res.json({ success: true });
    });
  } catch (err) {
    next(err);
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('authToken');
  res.json({ success: true });
});

// Image Upload Endpoint
app.post('/api/upload', requireAuth, uploadLimiter, csrfProtection, upload.single('file'), async (req, res, next) => {
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

// GET Current User Info
app.get('/api/auth/me', requireAuth, apiLimiter, (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  db.get("SELECT id, email, organisation_id, role, email_verified FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user.id,
      email: user.email,
      organisationId: user.organisation_id,
      role: user.role,
      emailVerified: user.email_verified === 1
    });
  });
});

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

// Short code generation functions
const crypto = require('crypto');

function generateShortCode() {
  let code = '';
  const charsLength = SHORT_CODE_CHARS.length;
  const maxValid = Math.floor(256 / charsLength) * charsLength; // 248 for 62 chars
  
  for (let i = 0; i < SHORT_CODE_LENGTH; i++) {
    let randomByte;
    do {
      randomByte = crypto.randomBytes(1)[0];
    } while (randomByte >= maxValid);
    
    code += SHORT_CODE_CHARS[randomByte % charsLength];
  }
  return code;
}

function ensureUniqueShortCode(db, callback) {
  let attempts = 0;
  const tryGenerate = () => {
    const code = generateShortCode();
    db.get("SELECT 1 FROM cards WHERE short_code = ?", [code], (err, row) => {
      if (err) return callback(err);
      if (!row) return callback(null, code);
      attempts++;
      if (attempts > 10) return callback(new Error('Failed to generate unique short code'));
      tryGenerate();
    });
  };
  tryGenerate();
}

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

// GET All Cards (Admin Dashboard)
app.get('/api/admin/cards', requireAuth, apiLimiter, (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Owners see all cards in organisation, members see only their own
  let query, params;
  const isOwner = req.user.role === 'owner';
  
  if (isOwner && req.user.organisationId) {
    // First, ensure organisation has a slug - if not, generate and save it
    db.get("SELECT slug, name FROM organisations WHERE id = ?", [req.user.organisationId], (err, orgRow) => {
      if (err) return next(err);
      
      let orgSlug = orgRow?.slug;
      // If organization doesn't have a slug, generate one from the organization name
      if (!orgSlug && orgRow?.name) {
        // Fix ReDoS: use separate replace calls instead of alternation in single regex
        const generatedSlug = orgRow.name.toLowerCase()
          .trim()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+/, '')  // Remove leading dashes (no alternation)
          .replace(/-+$/, '')  // Remove trailing dashes (no alternation)
          || 'organization';
        // Update organization with generated slug
        db.run("UPDATE organisations SET slug = ? WHERE id = ?", [generatedSlug, req.user.organisationId], (err) => {
          if (err) return next(err);
          orgSlug = generatedSlug;
          executeQuery(orgSlug);
        });
      } else {
        executeQuery(orgSlug);
      }
      
      function executeQuery(orgSlugValue) {
        // Owner with organization: get all users and their cards (LEFT JOIN to include users without cards)
        const query = `
          SELECT 
            u.id as user_id,
            u.email as user_email,
            u.role as user_role,
            u.created_at as user_created_at,
            c.slug,
            c.short_code,
            c.data
          FROM users u
          LEFT JOIN cards c ON c.user_id = u.id
          WHERE u.organisation_id = ?
          ORDER BY u.created_at DESC, c.created_at DESC
        `;
        const params = [req.user.organisationId];
        
        db.all(query, params, (err, rows) => {
          if (err) {
            log('GET /api/admin/cards - ERROR', { error: err.message, userId: req.user.id, role: req.user.role });
            return next(err);
          }
          
          log('GET /api/admin/cards - Query result', { 
            isOwner, 
            organisationId: req.user.organisationId,
            orgSlug: orgSlugValue,
            queryUsed: 'org-query',
            rowCount: rows.length,
            firstRowKeys: rows.length > 0 ? Object.keys(rows[0]) : [],
            firstRowSample: rows.length > 0 ? rows[0] : null
          });
          
          const list = rows.map(row => {
            // For owners with organization, we use LEFT JOIN so users without cards have row.data = null
            // User info is always present (from users table)
            const result = {
              userId: row.user_id,
              userEmail: row.user_email,
              userRole: row.user_role,
              userCreatedAt: row.user_created_at,
              slug: row.slug || null,
              shortCode: row.short_code || null,
              orgSlug: orgSlugValue || null,
              name: '',
              title: '',
              avatar: null,
              email: ''
            };
            
            // If user has a card, parse the card data
            if (row.slug && row.data) {
              try {
                const parsed = JSON.parse(row.data);
                result.name = `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim();
                result.title = parsed.personal?.title || '';
                result.avatar = parsed.images?.avatar || null;
                result.email = (parsed.contact?.email || '').toLowerCase();
              } catch (e) {
                result.name = 'Invalid card data';
                result.email = row.user_email;
              }
            } else {
              // User has no cards - leave name empty
              result.name = '';
              result.email = row.user_email;
            }
            
            return result;
          });
          
          log('GET /api/admin/cards - Response', { 
            count: list.length, 
            hasUserEmail: !!list[0]?.userEmail, 
            userEmail: list[0]?.userEmail,
            userId: list[0]?.userId,
            userRole: list[0]?.userRole,
            orgSlug: list[0]?.orgSlug
          });
          res.json(list);
        });
      }
    });
    
    return; // Exit early, we'll handle the response in the callback
  } else if (isOwner) {
    // Owner without organization: get own cards with user info
    query = `
      SELECT c.slug, c.short_code, c.data, c.user_id, u.email as user_email, u.role as user_role, u.created_at as user_created_at, o.slug as org_slug
      FROM cards c
      JOIN users u ON c.user_id = u.id
      LEFT JOIN organisations o ON u.organisation_id = o.id
      WHERE c.user_id = ?
      ORDER BY c.created_at DESC
    `;
    params = [req.user.id];
  } else {
    // Member: get own cards only (no user info needed)
    query = `
      SELECT c.slug, c.short_code, c.data, o.slug as org_slug
      FROM cards c
      JOIN users u ON c.user_id = u.id
      LEFT JOIN organisations o ON u.organisation_id = o.id
      WHERE c.user_id = ?
    `;
    params = [req.user.id];
  }
  
  db.all(query, params, (err, rows) => {
    if (err) {
      log('GET /api/admin/cards - ERROR', { error: err.message, userId: req.user.id, role: req.user.role });
      return next(err);
    }
    
    log('GET /api/admin/cards - Query result', { 
      isOwner, 
      organisationId: req.user.organisationId,
      queryUsed: isOwner && req.user.organisationId ? 'org-query' : isOwner ? 'owner-query' : 'member-query',
      rowCount: rows.length,
      firstRowKeys: rows.length > 0 ? Object.keys(rows[0]) : [],
      firstRowSample: rows.length > 0 ? rows[0] : null  // Log the entire first row
    });
    
    const list = rows.map(row => {
      // For owners with organization, we use LEFT JOIN so users without cards have row.data = null
      if (isOwner && req.user.organisationId) {
        // User info is always present (from users table)
        // Ensure orgSlug is set - if null, we'll need to generate it or use a default
        let orgSlug = row.org_slug;
        // If org slug is null, try to get it from the organization
        if (!orgSlug && req.user.organisationId) {
          // This shouldn't happen if JOIN worked, but handle it just in case
          // We'll leave it as null and handle in frontend
        }
        
        const result = {
          userId: row.user_id,
          userEmail: row.user_email,
          userRole: row.user_role,
          userCreatedAt: row.user_created_at,
          slug: row.slug || null,
          shortCode: row.short_code || null,
          orgSlug: orgSlug || null,
          name: '',
          title: '',
          avatar: null,
          email: ''
        };
        
        // If user has a card, parse the card data
        if (row.slug && row.data) {
          try {
            const parsed = JSON.parse(row.data);
            result.name = `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim();
            result.title = parsed.personal?.title || '';
            result.avatar = parsed.images?.avatar || null;
            result.email = (parsed.contact?.email || '').toLowerCase();
          } catch (e) {
            result.name = 'Invalid card data';
            result.email = row.user_email;
          }
        } else {
          // User has no cards - leave name empty
          result.name = '';
          result.email = row.user_email;
        }
        
        return result;
      }
      
      // For other cases (owner without org, or member), use original logic
      try {
        const parsed = JSON.parse(row.data);
        const result = {
          slug: row.slug,
          shortCode: row.short_code || null,
          orgSlug: row.org_slug || null,
          name: `${parsed.personal?.firstName || ''} ${parsed.personal?.lastName || ''}`.trim(),
          title: parsed.personal?.title || '',
          avatar: parsed.images?.avatar || null,
          email: (parsed.contact?.email || '').toLowerCase()
        };
        
        // Add user info for owners (from JOIN query)
        if (isOwner && row.user_id) {
          result.userId = row.user_id;
          result.userEmail = row.user_email;
          result.userRole = row.user_role;
          result.userCreatedAt = row.user_created_at;
          result.orgSlug = row.org_slug || null;
        }
        
        return result;
      } catch (e) {
        const result = {
          slug: row.slug,
          shortCode: row.short_code || null,
          orgSlug: row.org_slug || null,
          name: 'Invalid data',
          title: '',
          avatar: null,
          email: ''
        };

        if (isOwner && row.user_id) {
          result.userId = row.user_id;
          result.userEmail = row.user_email;
          result.userRole = row.user_role;
          result.userCreatedAt = row.user_created_at;
        }

        return result;
      }
    });
    
    log('GET /api/admin/cards - Response', { 
      count: list.length, 
      hasUserInfo: list.filter(c => c.userEmail).length,
      sampleCard: list.length > 0 ? { 
        slug: list[0].slug, 
        hasUserEmail: !!list[0].userEmail, 
        userEmail: list[0].userEmail,
        userId: list[0].userId,
        userRole: list[0].userRole
      } : null
    });
    res.json(list);
  });
});

// GET Short Code Card (Public endpoint - short code lookup)
// MUST come FIRST before other /api/cards routes to avoid route conflicts
const shortCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many short code lookup attempts',
  standardHeaders: true,
  legacyHeaders: false
});

app.get('/api/cards/short/:shortCode', cardReadLimiter, (req, res, next) => {
  const shortCode = (req.params.shortCode || '').trim();
  log(`[API] GET /api/cards/short/${shortCode} - Request received`);
  
  // Validate: exactly 7 alphanumeric characters
  if (!shortCode || shortCode.length !== 7) {
    log(`[API] Short code validation failed: length=${shortCode?.length || 0}`);
    return res.status(400).json({ error: `Short code must be exactly ${SHORT_CODE_LENGTH} characters` });
  }
  
  if (!new RegExp(`^[a-zA-Z0-9]{${SHORT_CODE_LENGTH}}$`).test(shortCode)) {
    log(`[API] Short code validation failed: invalid format`);
    return res.status(400).json({ error: 'Short code must contain only letters and numbers' });
  }
  
  log(`[API] Short code validated, querying database...`);
  // Short codes are case-sensitive, so use exact match
  // Also get organization slug so frontend can fetch correct settings
  db.get(`
    SELECT c.data, c.short_code, o.slug as org_slug
    FROM cards c
    JOIN users u ON c.user_id = u.id
    LEFT JOIN organisations o ON u.organisation_id = o.id
    WHERE c.short_code = ?
  `, [shortCode], (err, row) => {
    if (err) {
      console.error('[API] Database error fetching short code:', err);
      return next(err);
    }
    if (!row) {
      log(`[API] Short code not found in database: ${shortCode}`);
      return res.status(404).json({ error: "Card not found" });
    }
    try {
      const cardData = JSON.parse(row.data);
      // Include short_code and org_slug in response for frontend
      cardData._shortCode = row.short_code;
      if (row.org_slug) {
        cardData._orgSlug = row.org_slug;
      }
      log(`[API] Short code found, returning card data (has personal: ${!!cardData.personal}, org_slug: ${row.org_slug})`);
      res.json(cardData);
    } catch (e) {
      console.error('[API] Error parsing card data:', e);
      next(e);
    }
  });
});

// GET Card Preview Image (Social Media Meta Tag)
// MUST come BEFORE org-scoped route so /preview.png matches before being interpreted as cardSlug
// Supports both slug and short_code identifiers
// Route pattern: /api/cards/:identifier/preview.png
app.get('/api/cards/:identifier/preview.png', cardReadLimiter, [
  param('identifier').trim().matches(/^[a-zA-Z0-9-]+$/).withMessage('Invalid identifier')
], handleValidationErrors, async (req, res, next) => {
  try {
    const identifier = req.params.identifier; // Keep original case for short_code lookup
    const identifierLower = identifier.toLowerCase(); // For slug lookup

    // Check cache first (use lowercase for cache key)
    const cachedPath = resolveCachePath(identifierLower);
    if (cachedPath) {
      try {
        const stat = await fs.promises.stat(cachedPath);
        // Check cache age (24 hours)
        if (Date.now() - stat.mtimeMs < PREVIEW_CACHE_MAX_AGE) {
          const cachedBuffer = await fs.promises.readFile(cachedPath);
          res.set({
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=86400', // 24 hours
            'ETag': `"${stat.mtime.getTime()}"`
          });
          return res.send(cachedBuffer);
        }
      } catch (err) {
        // Cache miss or stat error, proceed to generate
        if (err.code !== 'ENOENT') {
          console.error('[Preview] Cache stat error:', err.message);
        }
      }
    }

    // Try to find card by short_code first (exact match)
    let cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code, c.slug, u.organisation_id
        FROM cards c
        JOIN users u ON c.user_id = u.id
        WHERE c.short_code = ?
      `, [identifier], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    // If not found by short_code, try by slug (case-insensitive)
    if (!cardRow) {
      cardRow = await new Promise((resolve, reject) => {
        db.get(`
          SELECT c.data, c.short_code, c.slug, u.organisation_id
          FROM cards c
          JOIN users u ON c.user_id = u.id
          WHERE LOWER(c.slug) = ?
          LIMIT 1
        `, [identifierLower], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
    }

    if (!cardRow) {
      console.log('[Preview] Card not found:', identifier);
      return res.status(404).json({ error: 'Card not found' });
    }

    let cardData;
    try {
      cardData = JSON.parse(cardRow.data);
    } catch (e) {
      console.error('[Preview] Failed to parse card data:', e.message);
      return res.status(500).json({ error: 'Invalid card data' });
    }

    console.log('[Preview] Card data loaded for:', identifier);
    console.log('[Preview] Card avatar URL:', cardData.images?.avatar || '(none)');
    console.log('[Preview] Card name:', cardData.personal?.firstName, cardData.personal?.lastName);

    // Privacy Check: Return generic preview if card requires interaction or has obfuscation
    const privacy = cardData.privacy || {};
    if (privacy.requireInteraction || privacy.clientSideObfuscation) {
      console.log('[Preview] Privacy protection active for:', identifier);
      const genericImage = await generateGenericPreviewImage();
      if (!genericImage) {
        return res.status(500).json({ error: 'Failed to generate preview' });
      }

      res.set({
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=3600' // 1 hour for generic
      });
      return res.send(genericImage);
    }

    // Generate preview image
    const themeColor = cardData.theme?.color || 'indigo';
    const previewBuffer = await generatePreviewImage(cardData, themeColor);

    if (!previewBuffer) {
      console.error('[Preview] Failed to generate preview image');
      return res.status(500).json({ error: 'Failed to generate preview' });
    }

    // Write to cache atomically
    if (cachedPath) {
      await writeToCacheAtomic(`preview_${identifier}.png`, previewBuffer);
    }

    // Return generated preview
    res.set({
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=86400' // 24 hours
    });
    res.send(previewBuffer);
  } catch (err) {
    console.error('[Preview] Endpoint error:', err.message);
    next(err);
  }
});

// GET Org-scoped Card (Public endpoint - org slug + card slug)
// MUST come after /api/cards/short/:shortCode and /api/cards/:identifier/preview.png
app.get('/api/cards/:orgSlug/:cardSlug', cardReadLimiter, [
  param('orgSlug').trim().matches(/^[a-z0-9-]+$/).withMessage('Invalid org slug'),
  param('cardSlug').trim().matches(/^[a-z0-9-]+$/).withMessage('Invalid card slug')
], handleValidationErrors, (req, res, next) => {
  const orgSlug = req.params.orgSlug.toLowerCase();
  const cardSlug = req.params.cardSlug.toLowerCase();
  log(`[API] GET /api/cards/${orgSlug}/${cardSlug} - Request received`);
  
  // Lookup organization by slug
  db.get("SELECT id FROM organisations WHERE slug = ?", [orgSlug], (err, org) => {
    if (err) {
      console.error('[API] Database error fetching org:', err);
      return next(err);
    }
    if (!org) {
      log(`[API] Organization not found: ${orgSlug}`);
      return res.status(404).json({ error: "Card not found" }); // Generic 404, no info leakage
    }
    
    log(`[API] Organization found (id: ${org.id}), querying card...`);
    // Find card within that organization
    db.get(`
      SELECT c.data, c.short_code 
      FROM cards c
      JOIN users u ON c.user_id = u.id
      WHERE c.slug = ? AND u.organisation_id = ?
      LIMIT 1
    `, [cardSlug, org.id], (err, row) => {
      if (err) {
        console.error('[API] Database error fetching card:', err);
        return next(err);
      }
      if (!row) {
        log(`[API] Card not found: ${cardSlug} in org ${orgSlug}`);
        return res.status(404).json({ error: "Card not found" });
      }
      try {
        const cardData = JSON.parse(row.data);
        // Include short_code in response for frontend QR generation
        cardData._shortCode = row.short_code;
        log(`[API] Card found, returning card data (has personal: ${!!cardData.personal})`);
        res.json(cardData);
      } catch (e) {
        console.error('[API] Error parsing card data:', e);
        next(e);
      }
    });
  });
});

// GET Single Card (Legacy endpoint - returns first match by slug, deprecated)
app.get('/api/cards/:slug', cardReadLimiter, [
  slugValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();
  // Public endpoint - get first card with this slug (multiple users can have same slug)
  // DEPRECATED: Use /api/cards/:orgSlug/:cardSlug or /api/cards/short/:shortCode instead
  db.get("SELECT data, short_code FROM cards WHERE slug = ? LIMIT 1", [slug], (err, row) => {
    if (err) return next(err);
    if (!row) return res.status(404).json({ error: "Card not found" });
    try {
      const cardData = JSON.parse(row.data);
      // Include short_code in response for frontend QR generation
      cardData._shortCode = row.short_code;
      res.setHeader('X-Deprecated', 'true');
      res.json(cardData);
    } catch (e) {
      next(e);
    }
  });
});

// SAVE/UPDATE Card
app.post('/api/cards/:slug', requireAuth, apiLimiter, csrfProtection, [
  slugValidation,
  ...cardDataValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();
  
  // Sanitize and validate the data structure
  const sanitizedData = {
    personal: {
      firstName: (req.body.personal?.firstName || '').trim().substring(0, 100),
      lastName: (req.body.personal?.lastName || '').trim().substring(0, 100),
      title: (req.body.personal?.title || '').trim().substring(0, 200),
      company: (req.body.personal?.company || '').trim().substring(0, 200),
      bio: (req.body.personal?.bio || '').trim().substring(0, 1000),
      location: (req.body.personal?.location || '').trim().substring(0, 200)
    },
    contact: {
      email: (req.body.contact?.email || '').trim(),
      phone: (req.body.contact?.phone || '').trim().substring(0, 50),
      website: (req.body.contact?.website || '').trim()
    },
    social: {
      linkedin: (req.body.social?.linkedin || '').trim(),
      twitter: (req.body.social?.twitter || '').trim(),
      instagram: (req.body.social?.instagram || '').trim(),
      github: (req.body.social?.github || '').trim()
    },
    theme: req.body.theme || { color: 'indigo', style: 'modern' },
    images: {
      avatar: (req.body.images?.avatar || '').trim().substring(0, 500),
      banner: (req.body.images?.banner || '').trim().substring(0, 500)
    },
    links: (req.body.links || []).map(link => ({
      id: link.id || Date.now(),
      title: (link.title || '').trim().substring(0, 200),
      url: (link.url || '').trim(),
      icon: link.icon || 'link'
    })).filter(link => link.url && validator.isURL(link.url, { protocols: ['http', 'https'] })),
    privacy: {
      requireInteraction: typeof req.body.privacy?.requireInteraction === 'boolean' ? req.body.privacy.requireInteraction : true,
      clientSideObfuscation: typeof req.body.privacy?.clientSideObfuscation === 'boolean' ? req.body.privacy.clientSideObfuscation : false,
      blockRobots: typeof req.body.privacy?.blockRobots === 'boolean' ? req.body.privacy.blockRobots : false
    }
  };

  // Ensure user is authenticated
  if (!req.user.id || !req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Determine target userId for card creation
  // Owners can create cards for other users in their organization
  // Members can only create cards for themselves
  let targetUserId = req.user.id; // Default to current user
  
  // Helper function to proceed with card save using determined targetUserId
  const proceedWithCardSave = (finalTargetUserId) => {
    // Get organization settings to enforce policies
    getOrganizationSettings(req.user.organisationId, (err, orgSettings) => {
      if (err) return next(err);
    
    // Enforce default_organisation - override user's company field
    if (orgSettings.default_organisation) {
      sanitizedData.personal.company = orgSettings.default_organisation;
    }
    
    // Enforce theme customisation policy
    if (!orgSettings.allow_theme_customisation) {
      // If theme customisation not allowed, validate theme colour is in org's theme_colours
      const requestedColor = sanitizedData.theme?.color;
      const allowedColors = orgSettings.theme_colors || [];
      const colorExists = allowedColors.some(c => c.name === requestedColor);
      
      if (!colorExists && requestedColor) {
        // Use first available color from org's palette, or default to 'indigo'
        sanitizedData.theme.color = allowedColors.length > 0 ? allowedColors[0].name : 'indigo';
      }
    }
    
    // Enforce image customisation policy
    if (!orgSettings.allow_image_customisation) {
      // Remove custom images if not allowed
      sanitizedData.images.avatar = '';
      sanitizedData.images.banner = '';
    }
    
    // Enforce links customisation policy
    if (!orgSettings.allow_links_customisation) {
      // Remove all custom links if not allowed
      sanitizedData.links = [];
    }
    
    // Enforce privacy customisation policy
    if (!orgSettings.allow_privacy_customisation) {
      // Reset to default privacy settings if customisation not allowed
      // Get existing card to preserve current privacy settings if they match defaults
      db.get("SELECT data FROM cards WHERE slug = ? AND user_id = ?", [slug, finalTargetUserId], (err, existingCard) => {
        if (err) return next(err);
        
        if (existingCard) {
          try {
            const existingData = JSON.parse(existingCard.data);
            // Only reset if user tried to change privacy settings
            const privacyChanged = 
              (req.body.privacy?.requireInteraction !== undefined && 
               req.body.privacy.requireInteraction !== existingData.privacy?.requireInteraction) ||
              (req.body.privacy?.clientSideObfuscation !== undefined && 
               req.body.privacy.clientSideObfuscation !== existingData.privacy?.clientSideObfuscation) ||
              (req.body.privacy?.blockRobots !== undefined && 
               req.body.privacy.blockRobots !== existingData.privacy?.blockRobots);
            
            if (privacyChanged) {
              // Keep existing privacy settings (don't allow changes)
              sanitizedData.privacy = existingData.privacy || {
                requireInteraction: true,
                clientSideObfuscation: false,
                blockRobots: false
              };
            } else {
              // No change attempted, use existing
              sanitizedData.privacy = existingData.privacy || sanitizedData.privacy;
            }
          } catch (e) {
            // If parsing fails, use defaults
            sanitizedData.privacy = {
              requireInteraction: true,
              clientSideObfuscation: false,
              blockRobots: false
            };
          }
        } else {
          // New card, use defaults
          sanitizedData.privacy = {
            requireInteraction: true,
            clientSideObfuscation: false,
            blockRobots: false
          };
        }
        
        // Check if card exists to get short code, or generate new one
        db.get("SELECT short_code FROM cards WHERE slug = ? AND user_id = ?", [slug, finalTargetUserId], (err, existingCardWithCode) => {
          if (err) return next(err);
          
          const existingShortCode = existingCardWithCode?.short_code;
          
          // If card exists with short code, use it; otherwise generate new one
          if (existingShortCode) {
            // Card exists with short code, just update data
            const jsonContent = JSON.stringify(sanitizedData);
            
            const query = `
              UPDATE cards 
              SET data = ?, updated_at = CURRENT_TIMESTAMP
              WHERE slug = ? AND user_id = ?
            `;

            db.run(query, [jsonContent, slug, finalTargetUserId], async function(err) {
              if (err) return next(err);
              await invalidatePreviewCache(slug, existingShortCode);
              res.json({ success: true, slug, shortCode: existingShortCode });
            });
          } else {
            // Card doesn't exist or has no short code, generate one
            ensureUniqueShortCode(db, (err, shortCode) => {
              if (err) return next(err);

              const jsonContent = JSON.stringify(sanitizedData);

              const query = `
                INSERT INTO cards (slug, user_id, short_code, data, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(slug, user_id) DO UPDATE SET
                  data = excluded.data,
                  short_code = COALESCE(cards.short_code, excluded.short_code),
                  updated_at = CURRENT_TIMESTAMP
              `;

              db.run(query, [slug, finalTargetUserId, shortCode, jsonContent], async function(err) {
                if (err) return next(err);
                await invalidatePreviewCache(slug, shortCode);
                res.json({ success: true, slug, shortCode });
              });
            });
          }
        });
      });
    } else {
      // Privacy customisation allowed, save normally
      // Check if card exists to get short code, or generate new one
      db.get("SELECT short_code FROM cards WHERE slug = ? AND user_id = ?", [slug, finalTargetUserId], (err, existingCardWithCode) => {
        if (err) return next(err);
        
        const existingShortCode = existingCardWithCode?.short_code;
        
        // If card exists with short code, use it; otherwise generate new one
        if (existingShortCode) {
          // Card exists with short code, just update data
          const jsonContent = JSON.stringify(sanitizedData);
          
          const query = `
            UPDATE cards 
            SET data = ?, updated_at = CURRENT_TIMESTAMP
            WHERE slug = ? AND user_id = ?
          `;

          db.run(query, [jsonContent, slug, finalTargetUserId], async function(err) {
            if (err) return next(err);
            await invalidatePreviewCache(slug, existingShortCode);
            res.json({ success: true, slug, shortCode: existingShortCode });
          });
        } else {
          // Card doesn't exist or has no short code, generate one
          ensureUniqueShortCode(db, (err, shortCode) => {
            if (err) return next(err);

            const jsonContent = JSON.stringify(sanitizedData);

            const query = `
              INSERT INTO cards (slug, user_id, short_code, data, updated_at)
              VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(slug, user_id) DO UPDATE SET
                data = excluded.data,
                short_code = COALESCE(cards.short_code, excluded.short_code),
                updated_at = CURRENT_TIMESTAMP
            `;

            db.run(query, [slug, finalTargetUserId, shortCode, jsonContent], async function(err) {
              if (err) return next(err);
              await invalidatePreviewCache(slug, shortCode);
              res.json({ success: true, slug, shortCode });
            });
          });
        }
      });
    }
    });
  };
  
  // Determine target user and proceed
  if (req.body.userId && req.user.role === 'owner') {
    // Owner wants to create card for another user - verify they're in same organization
    db.get("SELECT id, organisation_id FROM users WHERE id = ?", [req.body.userId], (err, targetUser) => {
      if (err) return next(err);
      if (!targetUser) {
        return res.status(404).json({ error: 'Target user not found' });
      }
      if (targetUser.organisation_id !== req.user.organisationId) {
        return res.status(403).json({ error: 'Cannot create card for user outside your organization' });
      }
      // Valid target user, proceed with card creation
      proceedWithCardSave(req.body.userId);
    });
  } else {
    // Member provided userId - ignore it, they can only create for themselves
    // Or no userId provided - use current user
    proceedWithCardSave(req.user.id);
  }
});

// DELETE Card
app.delete('/api/cards/:slug', requireAuth, apiLimiter, csrfProtection, [
  slugValidation
], handleValidationErrors, async (req, res, next) => {
  const slug = req.params.slug.toLowerCase();
  // Ensure user is authenticated and can only delete their own cards
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // First, fetch the card to get short_code for cache invalidation
  db.get("SELECT short_code FROM cards WHERE slug = ? AND user_id = ?", [slug, req.user.id], (err, card) => {
    if (err) return next(err);
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const shortCode = card.short_code;

    // Now delete the card
    db.run("DELETE FROM cards WHERE slug = ? AND user_id = ?", [slug, req.user.id], async function(err) {
      if (err) return next(err);
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Card not found' });
      }

      // Invalidate cache for both slug and short_code
      await invalidatePreviewCache(slug, shortCode);

      res.json({ success: true });
    });
  });
});

// Helper function to get organization settings
const getOrganizationSettings = (organisationId, callback) => {
  db.all("SELECT key, value FROM organisation_settings WHERE organisation_id = ?", [organisationId], (err, rows) => {
    if (err) return callback(err, null);
    
    const settings = {};
    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings[row.key] = JSON.parse(row.value);
        } else if (row.key.startsWith('allow_')) {
          settings[row.key] = row.value === 'true';
        } else {
          settings[row.key] = row.value;
        }
      } catch (e) {
        console.error(`Error parsing setting ${row.key}:`, e);
      }
    });
    
    // Ensure defaults
    if (!settings.default_organisation) settings.default_organisation = 'My Organisation';
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) settings.theme_variant = 'swiish';
    if (settings.allow_theme_customisation === undefined) settings.allow_theme_customisation = true;
    if (settings.allow_image_customisation === undefined) settings.allow_image_customisation = true;
    if (settings.allow_links_customisation === undefined) settings.allow_links_customisation = true;
    if (settings.allow_privacy_customisation === undefined) settings.allow_privacy_customisation = true;
    
    callback(null, settings);
  });
};

// GET Public Settings (theme_colors and theme_variant, no auth required)
// Returns theme_colors and theme_variant from specified organization or default organization
// Accepts optional ?orgSlug= parameter to get settings for a specific organization
app.get('/api/settings', apiLimiter, (req, res, next) => {
  const orgSlug = req.query.orgSlug || 'default';
  
  // Get theme_colors and theme_variant from specified organization
  db.all(`
    SELECT os.key, os.value 
    FROM organisation_settings os
    JOIN organisations o ON os.organisation_id = o.id
    WHERE o.slug = ? AND os.key IN ('theme_colors', 'theme_variant')
  `, [orgSlug], (err, rows) => {
    if (err) {
      return next(err);
    }
    
    const settings = {};
    
    // Parse the rows
    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings.theme_colors = JSON.parse(row.value);
        } else if (row.key === 'theme_variant') {
          settings.theme_variant = row.value;
        }
      } catch (e) {
        console.error(`Error parsing setting ${row.key}:`, e);
      }
    });
    
    // Ensure defaults
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) {
      settings.theme_variant = 'swiish';
    }
    
    res.json(settings);
  });
});

// GET Settings (Admin - full settings)
app.get('/api/admin/settings', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  // Ensure user is authenticated and has organization
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  db.all("SELECT key, value FROM organisation_settings WHERE organisation_id = ?", [req.user.organisationId], (err, rows) => {
    if (err) {
      log('GET /api/admin/settings - Database error', { error: err.message });
      return next(err);
    }
    
    log('GET /api/admin/settings - Raw database rows', {
      organisationId: req.user.organisationId,
      rows: rows.map(r => ({ key: r.key, value: r.value }))
    });
    
    const settings = {};
    rows.forEach(row => {
      try {
        if (row.key === 'theme_colors') {
          settings[row.key] = JSON.parse(row.value);
        } else if (row.key.startsWith('allow_')) {
          // Convert string "true"/"false" to boolean for override toggles
          settings[row.key] = row.value === 'true';
        } else {
          settings[row.key] = row.value;
        }
      } catch (e) {
        log(`Error parsing setting ${row.key}`, { error: e.message, value: row.value });
      }
    });
    
    // Ensure defaults exist
    if (!settings.default_organisation) {
      settings.default_organisation = 'My Organisation';
    }
    if (!settings.theme_colors || !Array.isArray(settings.theme_colors)) {
      settings.theme_colors = getDefaultThemeColors();
    }
    if (!settings.theme_variant) {
      settings.theme_variant = 'swiish';
    }
    // Ensure override toggles have defaults (true = allow customisation)
    if (settings.allow_theme_customisation === undefined) {
      settings.allow_theme_customisation = true;
    }
    if (settings.allow_image_customisation === undefined) {
      settings.allow_image_customisation = true;
    }
    if (settings.allow_links_customisation === undefined) {
      settings.allow_links_customisation = true;
    }
    if (settings.allow_privacy_customisation === undefined) {
      settings.allow_privacy_customisation = true;
    }
    
    log('GET /api/admin/settings - Returning settings', {
      organisationId: req.user.organisationId,
      settings: {
        default_organisation: settings.default_organisation,
        theme_variant: settings.theme_variant,
        allow_theme_customisation: settings.allow_theme_customisation,
        allow_image_customisation: settings.allow_image_customisation,
        allow_links_customisation: settings.allow_links_customisation,
        allow_privacy_customisation: settings.allow_privacy_customisation,
        theme_colors_count: settings.theme_colors?.length
      }
    });
    
    res.json(settings);
  });
});

// POST Settings (Update)
app.post('/api/admin/settings', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('default_organisation').optional().trim().isLength({ max: 200 }).withMessage('Organisation name too long'),
  body('theme_colors').optional().isArray().withMessage('Theme colors must be an array'),
  body('theme_colors.*.name').optional().trim().isLength({ max: 50 }).withMessage('Color name too long'),
  body('theme_colors.*.gradient').optional().trim().isLength({ max: 200 }).withMessage('Gradient too long'),
  body('theme_colors.*.button').optional().trim().isLength({ max: 200 }).withMessage('Button classes too long'),
  body('theme_colors.*.link').optional().trim().isLength({ max: 200 }).withMessage('Link classes too long'),
  body('theme_colors.*.text').optional().trim().isLength({ max: 200 }).withMessage('Text classes too long'),
  // Add validation for hex color properties
  body('theme_colors.*.gradientStyle').optional().trim().isLength({ max: 500 }).withMessage('Gradient style too long'),
  body('theme_colors.*.buttonStyle').optional().trim().isLength({ max: 50 }).withMessage('Button style too long'),
  body('theme_colors.*.linkStyle').optional().trim().isLength({ max: 50 }).withMessage('Link style too long'),
  body('theme_colors.*.textStyle').optional().trim().isLength({ max: 50 }).withMessage('Text style too long'),
  body('theme_colors.*.colorType').optional().isIn(['standard', 'custom']).withMessage('Invalid color type'),
  body('theme_colors.*.hexBase').optional().custom((value) => {
    if (value === null || value === undefined || value === '') return true;
    return /^#[0-9A-Fa-f]{6}$/.test(value);
  }).withMessage('Invalid hex base color'),
  body('theme_colors.*.hexSecondary').optional().custom((value) => {
    if (value === null || value === undefined || value === '') return true;
    return /^#[0-9A-Fa-f]{6}$/.test(value);
  }).withMessage('Invalid hex secondary color'),
  body('theme_colors.*.baseColor').optional().trim().isLength({ max: 50 }).withMessage('Base color too long'),
  body('theme_colors.*.secondaryColor').optional().trim().isLength({ max: 50 }).withMessage('Secondary color too long'),
  body('theme_colors.*.shade').optional().isInt({ min: 100, max: 900 }).withMessage('Invalid shade'),
  // Validation for override toggles
  body('allow_theme_customisation').optional().isBoolean().withMessage('allow_theme_customisation must be a boolean'),
  body('allow_image_customisation').optional().isBoolean().withMessage('allow_image_customisation must be a boolean'),
  body('allow_links_customisation').optional().isBoolean().withMessage('allow_links_customisation must be a boolean'),
  body('allow_privacy_customisation').optional().isBoolean().withMessage('allow_privacy_customisation must be a boolean')
], handleValidationErrors, (req, res, next) => {
  // Ensure user is authenticated and has organization
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { 
    default_organisation, 
    theme_colors,
  theme_variant,
    allow_theme_customisation,
    allow_image_customisation,
    allow_links_customisation,
    allow_privacy_customisation
  } = req.body;
  
  log('POST /api/admin/settings - Received settings update', {
    organisationId: req.user.organisationId,
    default_organisation,
    allow_theme_customisation,
    allow_image_customisation,
    allow_links_customisation,
    allow_privacy_customisation,
  theme_variant,
    theme_colors_count: theme_colors?.length
  });
  
  // Use promises to wait for all database operations to complete
  const promises = [];
  
  if (default_organisation !== undefined) {
    const sanitized = default_organisation.trim().substring(0, 200);
    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'default_organisation', sanitized],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }
  
  if (theme_colors !== undefined && Array.isArray(theme_colors)) {
    // Sanitize theme colors - preserve ALL properties, not just Tailwind classes
    const sanitized = theme_colors.map(color => {
      const sanitizedColor = {
        name: (color.name || '').trim().substring(0, 50),
        // Preserve Tailwind classes (may be null for hex colors)
        gradient: color.gradient ? (color.gradient || '').trim().substring(0, 200) : null,
        button: color.button ? (color.button || '').trim().substring(0, 200) : null,
        link: color.link ? (color.link || '').trim().substring(0, 200) : null,
        text: color.text ? (color.text || '').trim().substring(0, 200) : null,
        // Preserve hex styles (may be null for Tailwind colors)
        gradientStyle: color.gradientStyle || null,
        buttonStyle: color.buttonStyle || null,
        linkStyle: color.linkStyle || null,
        textStyle: color.textStyle || null,
        // Preserve color type and hex values
        colorType: color.colorType || null,
        hexBase: color.hexBase || null,
        hexSecondary: color.hexSecondary || null,
        // Preserve base color metadata
        baseColor: color.baseColor || null,
        secondaryColor: color.secondaryColor || null,
        shade: color.shade || null
      };
      return sanitizedColor;
    });
    
    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'theme_colors', JSON.stringify(sanitized)],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }

  if (theme_variant !== undefined) {
    const variant = typeof theme_variant === 'string' ? theme_variant.trim().substring(0, 50) : 'swiish';
    promises.push(new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        [req.user.organisationId, 'theme_variant', variant],
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    }));
  }
  
  // Save override toggles (convert boolean to "true"/"false" string for storage)
  const saveToggle = (key, value) => {
    if (value !== undefined && typeof value === 'boolean') {
      promises.push(new Promise((resolve, reject) => {
        db.run(
          "INSERT INTO organisation_settings (organisation_id, key, value, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organisation_id, key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
          [req.user.organisationId, key, value ? 'true' : 'false'],
          (err) => {
            if (err) return reject(err);
            resolve();
          }
        );
      }));
    }
  };
  
  saveToggle('allow_theme_customisation', allow_theme_customisation);
  saveToggle('allow_image_customisation', allow_image_customisation);
  saveToggle('allow_links_customisation', allow_links_customisation);
  saveToggle('allow_privacy_customisation', allow_privacy_customisation);
  
  // Wait for all database operations to complete before sending response
  Promise.all(promises)
    .then(() => {
      log('POST /api/admin/settings - Successfully saved all settings', {
        organisationId: req.user.organisationId,
        promisesCompleted: promises.length
      });
      res.json({ success: true });
    })
    .catch((err) => {
      log('POST /api/admin/settings - Error saving settings', { error: err.message, stack: err.stack });
      next(err);
    });
});

// --- USER MANAGEMENT ENDPOINTS (Owners only) ---

// GET All Users in Organization
app.get('/api/admin/users', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  db.all(
    "SELECT id, email, role, created_at FROM users WHERE organisation_id = ? ORDER BY created_at DESC",
    [req.user.organisationId],
    (err, rows) => {
      if (err) return next(err);
      res.json(rows);
    }
  );
});

// POST Create User (Manual creation by owner)
app.post('/api/admin/users', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('email').isEmail({ allow_display_name: false, require_tld: false }).withMessage('Valid email required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { email, password, role } = req.body;
  
  // Check if email already exists
  db.get("SELECT id FROM users WHERE email = ?", [email.toLowerCase()], async (err, existingUser) => {
    if (err) return next(err);
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if ACTIVE invitation exists (pending/sent, not expired)
    db.get(
      "SELECT id, status FROM invitations WHERE email = ? AND organisation_id = ? AND status IN ('pending', 'sent') AND expires_at > datetime('now')",
      [email.toLowerCase(), req.user.organisationId],
      (err, existingInvitation) => {
        if (err) return next(err);
        if (existingInvitation) {
          return res.status(400).json({
            error: 'An active invitation already exists for this email. Please wait for the user to accept the invitation or delete it first.',
            invitationStatus: existingInvitation.status
          });
        }

        // Create user (owner or member) - no restriction on creating members
        // Owners can always create members regardless of how many owners exist
        const userId = require('crypto').randomUUID();
        bcrypt.hash(password, 10, (err, passwordHash) => {
          if (err) return next(err);

          db.run(
            "INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified) VALUES (?, ?, ?, ?, ?, ?)",
            [userId, email.toLowerCase(), passwordHash, req.user.organisationId, role, 0],
            (err) => {
              if (err) return next(err);
              res.json({ success: true, userId, email: email.toLowerCase(), role });
            }
          );
        });
      }
    );
  });
});

// PATCH Update User Role
app.patch('/api/admin/users/:userId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('userId').isUUID().withMessage('Invalid user ID'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { userId } = req.params;
  const { role } = req.body;
  
  // Cannot change own role
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot change your own role' });
  }
  
  // Verify user is in same organization
  db.get("SELECT id, role FROM users WHERE id = ? AND organisation_id = ?", [userId, req.user.organisationId], (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // If changing from owner to member, check if this is the last owner
    if (user.role === 'owner' && role === 'member') {
      db.get("SELECT COUNT(*) as count FROM users WHERE organisation_id = ? AND role = 'owner'", [req.user.organisationId], (err, ownerCount) => {
        if (err) return next(err);
        if (ownerCount.count === 1) {
          return res.status(400).json({ error: 'Cannot remove last owner from organization' });
        }
        
        // Update role
        db.run("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [role, userId], (err) => {
          if (err) return next(err);
          res.json({ success: true });
        });
      });
    } else {
      // Update role
      db.run("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [role, userId], (err) => {
        if (err) return next(err);
        res.json({ success: true });
      });
    }
  });
});

// DELETE Remove User from Organization (Hard Delete with Cascade)
app.delete('/api/admin/users/:userId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('userId').isUUID().withMessage('Invalid user ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { userId } = req.params;

  // Cannot delete yourself
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }

  try {
    // Verify user is in same organization and get their info
    const user = await new Promise((resolve, reject) => {
      db.get("SELECT id, email, role, organisation_id FROM users WHERE id = ? AND organisation_id = ?",
        [userId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If deleting owner, check if this is the last owner
    if (user.role === 'owner') {
      const ownerCount = await new Promise((resolve, reject) => {
        db.get("SELECT COUNT(*) as count FROM users WHERE organisation_id = ? AND role = 'owner'",
          [req.user.organisationId],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          }
        );
      });

      if (ownerCount.count === 1) {
        return res.status(400).json({ error: 'Cannot delete last owner from organization' });
      }
    }

    // Capture snapshot of user and their cards for audit
    const cards = await new Promise((resolve, reject) => {
      db.all("SELECT * FROM cards WHERE user_id = ?", [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });

    const userSettings = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM user_settings WHERE user_id = ?", [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    // Log to audit before deletion
    await logAudit(
      'user_deleted',
      'user',
      userId,
      {
        user: user,
        cards: cards,
        settings: userSettings,
        card_count: cards.length
      },
      req.user.id,
      req.user.organisationId
    );

    // TRUE HARD DELETE - foreign keys will CASCADE to all child records
    // This will automatically delete:
    // - cards (ON DELETE CASCADE)
    // - user_settings (ON DELETE CASCADE)
    // - password_reset_tokens (ON DELETE CASCADE)
    // - email_verification_tokens (ON DELETE CASCADE)
    // - invitations where user is inviter (ON DELETE CASCADE)
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log(`[USER DELETED] User ${user.email} deleted by ${req.user.email}, ${cards.length} cards cascaded`);

    res.json({
      success: true,
      deletedCards: cards.length
    });

  } catch (err) {
    console.error('[USER DELETE ERROR]', err);
    next(err);
  }
});

// --- INVITATION ENDPOINTS ---

// POST Create and Send Invitation
app.post('/api/admin/invitations', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  body('email').isEmail().withMessage('Valid email required'),
  body('role').isIn(['owner', 'member']).withMessage('Role must be owner or member')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { email, role } = req.body;
  const emailLower = email.toLowerCase();

  try {
    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM users WHERE email = ?", [emailLower], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if ACTIVE invitation exists (pending/sent, not expired)
    // NOTE: This allows retries after failed/expired invitations
    const existingInvitation = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, status FROM invitations WHERE email = ? AND organisation_id = ? AND status IN ('pending', 'sent') AND expires_at > datetime('now')",
        [emailLower, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (existingInvitation) {
      return res.status(400).json({
        error: 'Active invitation already exists for this email',
        status: existingInvitation.status
      });
    }

    // Generate secure token
    const token = require('crypto').randomBytes(32).toString('hex');
    const invitationId = require('crypto').randomUUID();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Create invitation with status='pending' first
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO invitations (id, organisation_id, email, token, role, invited_by, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
        [invitationId, req.user.organisationId, emailLower, token, role, req.user.id, expiresAt.toISOString()],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Get organization name for email
    const org = await new Promise((resolve, reject) => {
      db.get("SELECT name FROM organisations WHERE id = ?", [req.user.organisationId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    const orgName = org ? org.name : 'Organization';

    // Attempt to send email
    let emailStatus = 'sent';
    let emailError = null;

    try {
      if (emailTransporter) {
        const invitationUrl = `${APP_URL}/invite/${token}`;
        const emailHtml = `
          <h2>You've been invited to join ${orgName}</h2>
          <p>You've been invited to join ${orgName} on Swiish. Click the link below to accept the invitation and create your account.</p>
          <p><a href="${invitationUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Accept Invitation</a></p>
          <p>This invitation will expire in 7 days.</p>
          <p>If you didn't expect this invitation, you can safely ignore this email.</p>
        `;
        const emailText = `You've been invited to join ${orgName} on Swiish. Visit ${invitationUrl} to accept the invitation. This invitation expires in 7 days.`;

        await emailTransporter.sendMail({
          from: SMTP_FROM,
          to: emailLower,
          subject: `Invitation to join ${orgName} on Swiish`,
          text: emailText,
          html: emailHtml
        });
      }
    } catch (emailErr) {
      console.error('Failed to send invitation email:', emailErr);
      emailStatus = 'failed';
      emailError = emailErr.message;
    }

    // Update invitation status
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE invitations SET status = ? WHERE id = ?",
        [emailStatus, invitationId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Log audit event
    await logAudit(
      'invitation_created',
      'invitation',
      invitationId,
      { email: emailLower, role, status: emailStatus },
      req.user.id,
      req.user.organisationId
    );

    // Return success with status info
    res.json({
      success: true,
      invitationId,
      expiresAt: expiresAt.toISOString(),
      status: emailStatus,
      ...(emailError && { warning: 'Invitation created but email failed to send. You can retry from the admin panel.' })
    });

  } catch (err) {
    next(err);
  }
});

// GET Invitation Details (Public)
app.get('/api/invitations/:token', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid invitation token')
], handleValidationErrors, (req, res, next) => {
  const { token } = req.params;
  
  db.get(
    "SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, o.name as organization_name FROM invitations i JOIN organisations o ON i.organisation_id = o.id WHERE i.token = ?",
    [token],
    (err, invitation) => {
      if (err) return next(err);
      if (!invitation) {
        return res.status(404).json({ error: 'Invitation not found' });
      }
      if (invitation.accepted_at) {
        return res.status(400).json({ error: 'Invitation has already been accepted' });
      }
      if (new Date(invitation.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Invitation has expired' });
      }
      res.json({
        email: invitation.email,
        role: invitation.role,
        organisationName: invitation.organization_name,
        expiresAt: invitation.expires_at
      });
    }
  );
});

// POST Accept Invitation
app.post('/api/invitations/:token/accept', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid invitation token'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  const { token } = req.params;
  const { password } = req.body;
  
  // Get invitation
  db.get(
    "SELECT * FROM invitations WHERE token = ?",
    [token],
    async (err, invitation) => {
      if (err) return next(err);
      if (!invitation) {
        return res.status(404).json({ error: 'Invitation not found' });
      }
      if (invitation.accepted_at) {
        return res.status(400).json({ error: 'Invitation has already been accepted' });
      }
      if (new Date(invitation.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Invitation has expired' });
      }
      
      // Check if user already exists
      db.get("SELECT id FROM users WHERE email = ?", [invitation.email], async (err, existingUser) => {
        if (err) return next(err);
        if (existingUser) {
          return res.status(400).json({ error: 'User with this email already exists' });
        }
        
        // Create user
        const userId = require('crypto').randomUUID();
        const passwordHash = await bcrypt.hash(password, 10);
        
        db.run(
          "INSERT INTO users (id, email, password_hash, organisation_id, role, email_verified) VALUES (?, ?, ?, ?, ?, ?)",
          [userId, invitation.email, passwordHash, invitation.organisation_id, invitation.role, 0],
          (err) => {
            if (err) return next(err);
            
            // Mark invitation as accepted
            db.run(
              "UPDATE invitations SET accepted_at = CURRENT_TIMESTAMP, status = 'accepted' WHERE id = ?",
              [invitation.id],
              async (err) => {
                if (err) {
                  console.error('Failed to mark invitation as accepted:', err);
                  // Don't fail the request
                } else {
                  // Log audit event for invitation acceptance
                  try {
                    await logAudit(
                      'invitation_accepted',
                      'invitation',
                      invitation.id,
                      { email: invitation.email, role: invitation.role },
                      userId,
                      invitation.organisation_id
                    );
                  } catch (auditErr) {
                    console.error('Failed to log invitation acceptance audit:', auditErr);
                    // Don't fail the request if audit logging fails
                  }
                }
                
                // Generate JWT token
                const jwtToken = jwt.sign(
                  {
                    user_id: userId,
                    organisation_id: invitation.organisation_id,
                    role: invitation.role
                  },
                  JWT_SECRET,
                  { expiresIn: JWT_EXPIRES_IN }
                );
                
                // Set httpOnly cookie
                res.cookie('authToken', jwtToken, {
                  httpOnly: true,
                  secure: NODE_ENV === 'production',
                  sameSite: 'strict',
                  maxAge: 24 * 60 * 60 * 1000 // 24 hours
                });
                
                res.json({ success: true, userId, email: invitation.email, role: invitation.role });
              }
            );
          }
        );
      });
    }
  );
});

// --- INVITATION MANAGEMENT ENDPOINTS ---

// GET List all invitations for organization
app.get('/api/admin/invitations', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all(
    `SELECT
      i.id,
      i.email,
      i.role,
      i.status,
      i.created_at,
      i.expires_at,
      i.accepted_at,
      u.email as invited_by_email
    FROM invitations i
    LEFT JOIN users u ON i.invited_by = u.id
    WHERE i.organisation_id = ?
    ORDER BY i.created_at DESC`,
    [req.user.organisationId],
    (err, invitations) => {
      if (err) return next(err);
      res.json({ invitations });
    }
  );
});

// DELETE Cancel invitation
app.delete('/api/admin/invitations/:invitationId', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('invitationId').isUUID().withMessage('Invalid invitation ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { invitationId } = req.params;

  try {
    // Verify invitation belongs to organization
    const invitation = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, email, status, accepted_at FROM invitations WHERE id = ? AND organisation_id = ?",
        [invitationId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!invitation) {
      return res.status(404).json({ error: 'Invitation not found' });
    }

    // Don't allow deletion of accepted invitations (for audit trail)
    if (invitation.accepted_at) {
      return res.status(400).json({ error: 'Cannot delete accepted invitation' });
    }

    // Log audit before deletion
    await logAudit(
      'invitation_deleted',
      'invitation',
      invitationId,
      { email: invitation.email, status: invitation.status },
      req.user.id,
      req.user.organisationId
    );

    // Delete invitation
    await new Promise((resolve, reject) => {
      db.run("DELETE FROM invitations WHERE id = ?", [invitationId], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.json({ success: true });

  } catch (err) {
    next(err);
  }
});

// POST Retry sending failed invitation
app.post('/api/admin/invitations/:invitationId/retry', requireAuth, requireRole('owner'), apiLimiter, csrfProtection, [
  param('invitationId').isUUID().withMessage('Invalid invitation ID')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.organisationId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { invitationId } = req.params;

  try {
    // Get invitation
    const invitation = await new Promise((resolve, reject) => {
      db.get(
        `SELECT i.*, o.name as org_name
         FROM invitations i
         JOIN organisations o ON i.organisation_id = o.id
         WHERE i.id = ? AND i.organisation_id = ?`,
        [invitationId, req.user.organisationId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!invitation) {
      return res.status(404).json({ error: 'Invitation not found' });
    }

    // Only allow retry for failed or pending invitations
    if (invitation.status !== 'failed' && invitation.status !== 'pending') {
      return res.status(400).json({ error: `Cannot retry invitation with status: ${invitation.status}` });
    }

    // Check if expired
    if (new Date(invitation.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invitation has expired. Please delete and create a new one.' });
    }

    // Attempt to send email
    let emailStatus = 'sent';
    let emailError = null;

    try {
      if (emailTransporter) {
        const invitationUrl = `${APP_URL}/invite/${invitation.token}`;
        const emailHtml = `
          <h2>You've been invited to join ${invitation.org_name}</h2>
          <p>You've been invited to join ${invitation.org_name} on Swiish. Click the link below to accept the invitation and create your account.</p>
          <p><a href="${invitationUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Accept Invitation</a></p>
          <p>This invitation will expire in 7 days.</p>
          <p>If you didn't expect this invitation, you can safely ignore this email.</p>
        `;
        const emailText = `You've been invited to join ${invitation.org_name} on Swiish. Visit ${invitationUrl} to accept the invitation. This invitation expires in 7 days.`;

        await emailTransporter.sendMail({
          from: SMTP_FROM,
          to: invitation.email,
          subject: `Invitation to join ${invitation.org_name} on Swiish`,
          text: emailText,
          html: emailHtml
        });
      }
    } catch (emailErr) {
      console.error('Failed to send invitation email:', emailErr);
      emailStatus = 'failed';
      emailError = emailErr.message;
    }

    // Update invitation status
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE invitations SET status = ? WHERE id = ?",
        [emailStatus, invitationId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    // Log audit
    await logAudit(
      'invitation_retry',
      'invitation',
      invitationId,
      { email: invitation.email, new_status: emailStatus },
      req.user.id,
      req.user.organisationId
    );

    res.json({
      success: emailStatus === 'sent',
      status: emailStatus,
      ...(emailError && { error: 'Email failed to send. Please check SMTP configuration.' })
    });

  } catch (err) {
    next(err);
  }
});

// --- PASSWORD RESET ENDPOINTS ---

// POST Forgot Password (Request password reset)
app.post('/api/auth/forgot-password', apiLimiter, [
  body('email').isEmail().withMessage('Valid email required')
], handleValidationErrors, async (req, res, next) => {
  const { email } = req.body;
  const emailLower = email.toLowerCase();
  
  // Find user by email
  db.get("SELECT id, email FROM users WHERE email = ?", [emailLower], async (err, user) => {
    if (err) return next(err);
    
    // Always return success (don't reveal if email exists)
    if (!user) {
      return res.json({ success: true, message: 'If an account exists with this email, a password reset link has been sent' });
    }
    
    // Generate secure token
    const token = require('crypto').randomBytes(32).toString('hex');
    const tokenId = require('crypto').randomUUID();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry
    
    // Delete any existing unused tokens for this user
    db.run("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", [user.id], (err) => {
      if (err) {
        console.error('Error deleting old tokens:', err);
        // Continue anyway
      }
      
      // Create password reset token
      db.run(
        "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
        [tokenId, user.id, token, expiresAt.toISOString()],
        async (err) => {
          if (err) return next(err);
          
          // Send password reset email
          const resetUrl = `${APP_URL}/reset-password/${token}`;
          const emailHtml = `
            <h2>Password Reset Request</h2>
            <p>You requested to reset your password for your Swiish account. Click the link below to reset your password:</p>
            <p><a href="${resetUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
          `;
          const emailText = `You requested to reset your password. Visit ${resetUrl} to reset it. This link expires in 1 hour.`;
          
          try {
            if (emailTransporter) {
              await emailTransporter.sendMail({
                from: SMTP_FROM,
                to: emailLower,
                subject: 'Reset your Swiish password',
                text: emailText,
                html: emailHtml
              });
            }
          } catch (emailErr) {
            console.error('Failed to send password reset email:', emailErr);
            // Don't fail the request if email fails
          }
          
          res.json({ success: true, message: 'If an account exists with this email, a password reset link has been sent' });
        }
      );
    });
  });
});

// POST Reset Password (with token)
app.post('/api/auth/reset-password', apiLimiter, [
  body('token').isLength({ min: 64, max: 64 }).withMessage('Invalid reset token'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  const { token, password } = req.body;
  
  // Get reset token
  db.get(
    "SELECT prt.*, u.id as user_id FROM password_reset_tokens prt JOIN users u ON prt.user_id = u.id WHERE prt.token = ?",
    [token],
    async (err, resetToken) => {
      if (err) return next(err);
      if (!resetToken) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }
      if (resetToken.used_at) {
        return res.status(400).json({ error: 'This reset token has already been used' });
      }
      if (new Date(resetToken.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Reset token has expired' });
      }
      
      // Hash new password
      const passwordHash = await bcrypt.hash(password, 10);
      
      // Update user password
      db.run(
        "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [passwordHash, resetToken.user_id],
        (err) => {
          if (err) return next(err);
          
          // Mark token as used
          db.run(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
            [resetToken.id],
            (err) => {
              if (err) {
                console.error('Failed to mark token as used:', err);
                // Don't fail the request
              }
              
              res.json({ success: true, message: 'Password has been reset successfully' });
            }
          );
        }
      );
    }
  );
});

// POST Change Password (when logged in)
app.post('/api/auth/change-password', requireAuth, apiLimiter, csrfProtection, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
], handleValidationErrors, async (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { currentPassword, newPassword } = req.body;
  
  // Get user
  db.get("SELECT password_hash FROM users WHERE id = ?", [req.user.id], async (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    
    // Update password
    db.run(
      "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [passwordHash, req.user.id],
      (err) => {
        if (err) return next(err);
        res.json({ success: true, message: 'Password has been changed successfully' });
      }
    );
  });
});

// --- EMAIL VERIFICATION ENDPOINTS ---

// POST Send Verification Email
app.post('/api/auth/send-verification', requireAuth, apiLimiter, csrfProtection, async (req, res, next) => {
  if (!req.user.id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // Get user email
  db.get("SELECT email, email_verified FROM users WHERE id = ?", [req.user.id], async (err, user) => {
    if (err) return next(err);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }
    
    // Check for existing unused verification token
    db.get(
      "SELECT id FROM email_verification_tokens WHERE user_id = ? AND verified_at IS NULL AND expires_at > datetime('now')",
      [req.user.id],
      async (err, existingToken) => {
        if (err) return next(err);
        if (existingToken) {
          return res.status(400).json({ error: 'Verification email already sent. Please check your email or wait before requesting another.' });
        }
        
        // Generate verification token
        const token = require('crypto').randomBytes(32).toString('hex');
        const tokenId = require('crypto').randomUUID();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiry
        
        // Create verification token
        db.run(
          "INSERT INTO email_verification_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
          [tokenId, req.user.id, token, expiresAt.toISOString()],
          async (err) => {
            if (err) return next(err);
            
            // Send verification email
            const verifyUrl = `${APP_URL}/verify-email/${token}`;
            const emailHtml = `
              <h2>Verify Your Email Address</h2>
              <p>Please verify your email address by clicking the link below:</p>
              <p><a href="${verifyUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a></p>
              <p>This link will expire in 7 days.</p>
              <p>If you didn't create an account, you can safely ignore this email.</p>
            `;
            const emailText = `Please verify your email address by visiting ${verifyUrl}. This link expires in 7 days.`;
            
            try {
              if (emailTransporter) {
                await emailTransporter.sendMail({
                  from: SMTP_FROM,
                  to: user.email,
                  subject: 'Verify your Swiish email address',
                  text: emailText,
                  html: emailHtml
                });
              }
            } catch (emailErr) {
              console.error('Failed to send verification email:', emailErr);
              return res.status(500).json({ error: 'Failed to send verification email' });
            }
            
            res.json({ success: true, message: 'Verification email sent' });
          }
        );
      }
    );
  });
});

// GET Verify Email (with token)
app.get('/api/auth/verify-email/:token', publicReadLimiter, [
  param('token').isLength({ min: 64, max: 64 }).withMessage('Invalid verification token')
], handleValidationErrors, (req, res, next) => {
  const { token } = req.params;
  
  // Get verification token
  db.get(
    "SELECT evt.*, u.id as user_id, u.email FROM email_verification_tokens evt JOIN users u ON evt.user_id = u.id WHERE evt.token = ?",
    [token],
    (err, verificationToken) => {
      if (err) return next(err);
      if (!verificationToken) {
        return res.status(400).json({ error: 'Invalid or expired verification token' });
      }
      if (verificationToken.verified_at) {
        return res.status(400).json({ error: 'Email has already been verified' });
      }
      if (new Date(verificationToken.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Verification token has expired' });
      }
      
      // Mark email as verified
      db.run(
        "UPDATE users SET email_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [verificationToken.user_id],
        (err) => {
          if (err) return next(err);
          
          // Mark token as verified
          db.run(
            "UPDATE email_verification_tokens SET verified_at = CURRENT_TIMESTAMP WHERE id = ?",
            [verificationToken.id],
            (err) => {
              if (err) {
                console.error('Failed to mark token as verified:', err);
                // Don't fail the request
              }
              
              res.json({ success: true, message: 'Email verified successfully' });
            }
          );
        }
      );
    }
  );
});

// Dynamic per-card manifest endpoint
app.get('/manifest/:slug.json', publicReadLimiter, [
  identifierValidation
], handleValidationErrors, async (req, res, next) => {
  // Get original identifier (before lowercasing) to preserve short code case
  const originalIdentifier = req.params.slug;
  // Check if it's a short code (exactly 7 alphanumeric chars) - case sensitive
  const isShortCode = /^[a-zA-Z0-9]{7}$/.test(originalIdentifier);
  // Use original for short codes, lowercase for slugs
  const identifier = isShortCode ? originalIdentifier : originalIdentifier.toLowerCase();
  

  // Load base manifest from disk (fallback if needed)
  let baseManifest = {
    short_name: 'Swiish',
    name: 'Swiish',
    start_url: '.',
    display: 'standalone',
    background_color: '#020617',
    theme_color: '#020617',
    icons: [
      { src: '/swiish-logo.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }
    ]
  };

  try {
    const manifestPath = path.join(__dirname, 'public', 'manifest.json');
    try {
      const raw = await fs.promises.readFile(manifestPath, 'utf8');
      const parsed = JSON.parse(raw);
      baseManifest = {
        short_name: parsed.short_name || baseManifest.short_name,
        name: parsed.name || baseManifest.name,
        start_url: parsed.start_url || baseManifest.start_url,
        display: parsed.display || baseManifest.display,
        background_color: parsed.background_color || baseManifest.background_color,
        theme_color: parsed.theme_color || baseManifest.theme_color,
        icons: Array.isArray(parsed.icons) && parsed.icons.length > 0 ? parsed.icons : baseManifest.icons
      };
    } catch (readErr) {
      // File doesn't exist or can't be read - use default manifest
      // This is fine, we have a fallback
    }
  } catch (err) {
    console.error('Failed to read base manifest:', err);
  }

  // Look up card by short_code or slug - need both data and slug for icon generation
  const query = isShortCode 
    ? "SELECT data, slug FROM cards WHERE short_code = ?"
    : "SELECT data, slug FROM cards WHERE slug = ?";
    
  db.get(query, [identifier], (err, row) => {
    if (err) return next(err);
    
    if (!row) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Use the actual card slug for icon generation (not the short code or org slug)
    const cardSlug = row.slug;
    
    let cardName = 'Swiish Card';
    if (row && row.data) {
      try {
        const parsed = JSON.parse(row.data);
        const first = (parsed.personal?.firstName || '').trim();
        const last = (parsed.personal?.lastName || '').trim();
        const full = `${first} ${last}`.trim();
        cardName = full || parsed.personal?.company || cardName;
      } catch (e) {
        // fallback to default cardName
      }
    }

    // Use the identifier from URL for start_url (preserves short code or org-scoped routes)
    const startUrl = `/${identifier}/`;
    const manifest = {
      ...baseManifest,
      name: cardName,
      short_name: cardName.length > 20 ? cardName.slice(0, 20) : cardName,
      start_url: startUrl,
      scope: startUrl,
      icons: [
        { src: `/icons/${cardSlug}.svg`, sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
        { src: `/icons/${cardSlug}.svg`, sizes: '192x192', type: 'image/svg+xml' },
        { src: `/icons/${cardSlug}.svg`, sizes: '512x512', type: 'image/svg+xml' }
      ]
    };

    res.json(manifest);
  });
});

// Dynamic themed SVG icon endpoint
app.get('/icons/:slug.svg', publicReadLimiter, [
  identifierValidation
], handleValidationErrors, (req, res, next) => {
  const slug = req.params.slug.toLowerCase();

  // Get card data AND the user's organization_id in one query
  db.get(`
    SELECT c.data, u.organisation_id
    FROM cards c
    JOIN users u ON c.user_id = u.id
    WHERE c.slug = ?
  `, [slug], (err, row) => {
    if (err) return next(err);

    if (!row) {
      return res.status(404).type('image/svg+xml').send(`<svg xmlns="http://www.w3.org/2000/svg"><text>Card not found</text></svg>`);
    }

    let themeColor = 'indigo';
    if (row.data) {
      try {
        const parsed = JSON.parse(row.data);
        themeColor = parsed.theme?.color || 'indigo';
      } catch (e) {
        // fallback to indigo
      }
    }

    // Query settings for theme_colors from the card's ACTUAL organization
    const orgId = row.organisation_id;
    
    // Handle case where organisation_id might be null
    if (!orgId) {
      const fillColor = getThemeColorHex(themeColor);
      const svgPath = "M356.35,66.77h-59.65v-27.16c0-21.79-17.83-39.62-39.62-39.62H6.6C2.96,0,0,2.96,0,6.6v130.94c0,21.79,17.83,39.62,39.62,39.62h35.71c3.08,0,5.57-2.49,5.57-5.57v-78.41c0-14.59,11.82-26.41,26.41-26.41h16.52c3.65,0,6.6,2.96,6.6,6.6v8.49c0,3.65-2.96,6.6-6.6,6.6h-9.13c-3.65,0-6.6,2.96-6.6,6.6v76.53c0,3.08,2.49,5.57,5.57,5.57h143.42c21.79,0,39.62-17.83,39.62-39.62v-44.37h59.65c7.26,0,13.21,5.94,13.21,13.21v127.63c0,7.26-5.94,13.21-13.21,13.21H121.01c-7.26,0-13.21-5.94-13.21-13.21v-6.83c0-3.65-2.96-6.6-6.6-6.6h-13.21c-3.65,0-6.6,2.96-6.6,6.6v6.83c0,21.79,17.83,39.62,39.62,39.62h235.34c21.79,0,39.62-17.83,39.62-39.62v-127.63c0-21.79-17.83-39.62-39.62-39.62Z";
      const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg id="Layer_2" data-name="Layer 2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 395.96 273.63">
  <g id="Layer_1-2" data-name="Layer 1">
    <path fill="${fillColor}" d="${svgPath}"/>
  </g>
</svg>`;
      return res.type('image/svg+xml').send(svg);
    }
    
    db.get(`
      SELECT os.value 
      FROM organisation_settings os
      WHERE os.organisation_id = ? AND os.key = ?
    `, [orgId, 'theme_colors'], (settingsErr, settingsRow) => {
      let fillColor = '#4f46e5'; // default to indigo
      
      if (!settingsErr && settingsRow && settingsRow.value) {
        try {
          const theme_colors = JSON.parse(settingsRow.value);
          const colorEntry = theme_colors.find(c => c.name === themeColor);
          
          if (colorEntry) {
            // Use textStyle (hex value) or hexBase, fall back to colorMap
            fillColor = colorEntry.textStyle || colorEntry.hexBase || getThemeColorHex(themeColor);
          } else {
            // Color not found in settings, use colorMap
            fillColor = getThemeColorHex(themeColor);
          }
        } catch (e) {
          // Parse error, fall back to colorMap
          fillColor = getThemeColorHex(themeColor);
        }
      } else {
        // No settings found, use colorMap
        fillColor = getThemeColorHex(themeColor);
      }


      // SVG path from Swiish_Logo_Device.svg (extracted from the actual file)
      // viewBox: 0 0 395.96 273.63
      const svgPath = "M356.35,66.77h-59.65v-27.16c0-21.79-17.83-39.62-39.62-39.62H6.6C2.96,0,0,2.96,0,6.6v130.94c0,21.79,17.83,39.62,39.62,39.62h35.71c3.08,0,5.57-2.49,5.57-5.57v-78.41c0-14.59,11.82-26.41,26.41-26.41h16.52c3.65,0,6.6,2.96,6.6,6.6v8.49c0,3.65-2.96,6.6-6.6,6.6h-9.13c-3.65,0-6.6,2.96-6.6,6.6v76.53c0,3.08,2.49,5.57,5.57,5.57h143.42c21.79,0,39.62-17.83,39.62-39.62v-44.37h59.65c7.26,0,13.21,5.94,13.21,13.21v127.63c0,7.26-5.94,13.21-13.21,13.21H121.01c-7.26,0-13.21-5.94-13.21-13.21v-6.83c0-3.65-2.96-6.6-6.6-6.6h-13.21c-3.65,0-6.6,2.96-6.6,6.6v6.83c0,21.79,17.83,39.62,39.62,39.62h235.34c21.79,0,39.62-17.83,39.62-39.62v-127.63c0-21.79-17.83-39.62-39.62-39.62Z";

      const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg id="Layer_2" data-name="Layer 2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 395.96 273.63">
  <g id="Layer_1-2" data-name="Layer 1">
    <path fill="${fillColor}" d="${svgPath}"/>
  </g>
</svg>`;

      res.type('image/svg+xml').send(svg);
    });
  });
});

// Admin endpoint to view logs
app.get('/api/admin/logs', requireAuth, apiLimiter, (req, res, next) => {
  try {
    // Return last 100 lines
    const recentLogs = logLines.slice(-100);
    res.json({ logs: recentLogs, totalLines: logLines.length });
  } catch (err) {
    next(err);
  }
});

// QR Code Generation Endpoint
// GET: accepts slug or short code, generates QR with short code URL
app.get('/api/qr/:identifier', publicReadLimiter, [
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
app.post('/api/qr/:identifier', publicReadLimiter, [
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

// Error handling middleware (must be last)
app.use(errorHandler);

// Helper function to inject meta tags for social media sharing
async function injectMetaTags(html, cardIdentifier, displayIdentifier) {
  // cardIdentifier is what we use for lookups
  // displayIdentifier is what we show in preview URLs (might include orgSlug for org-scoped)

  // Try to find card by short_code, slug, or org-scoped combination
  let cardRow;

  // Check if it's an org-scoped lookup (contains /)
  if (displayIdentifier.includes('/')) {
    const [orgSlug, cardSlug] = displayIdentifier.split('/');
    // Look up by organization + card slug
    cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code
        FROM cards c
        JOIN users u ON c.user_id = u.id
        JOIN organisations o ON u.organisation_id = o.id
        WHERE LOWER(o.slug) = LOWER(?) AND LOWER(c.slug) = LOWER(?)
        LIMIT 1
      `, [orgSlug, cardSlug], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  } else {
    // Original logic for short code or slug lookup
    cardRow = await new Promise((resolve, reject) => {
      db.get(`
        SELECT c.data, c.short_code
        FROM cards c
        WHERE c.short_code = ? OR LOWER(c.slug) = LOWER(?)
        LIMIT 1
      `, [cardIdentifier, cardIdentifier], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  if (!cardRow) {
    return html; // Card not found, return unmodified HTML
  }

  try {
    const cardData = JSON.parse(cardRow.data);
    const privacy = cardData.privacy || {};

    // Privacy Leak Fix: "Block Robots" mode completely hides user identity
    if (privacy.blockRobots) {
      const robotsMeta = `
        <title>Private Card</title>
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex, nofollow">
      `;
      // Remove existing title tag to prevent duplicates
      html = html.replace(/<title>.*?<\/title>/i, '');
      // Insert before closing head tag
      return html.replace('</head>', robotsMeta + '</head>');
    }

    // Privacy Check: Don't expose preview for cards requiring interaction
    if (privacy.requireInteraction || privacy.clientSideObfuscation) {
      const privateMeta = `
        <title>Card Preview</title>
        <meta name="robots" content="noindex, follow">
      `;
      // Remove existing title tag to prevent duplicates
      html = html.replace(/<title>.*?<\/title>/i, '');
      return html.replace('</head>', privateMeta + '</head>');
    }

    // Safe to include preview - construct meta tags
    const firstName = escapeXml(cardData.personal?.firstName || '');
    const lastName = escapeXml(cardData.personal?.lastName || '');
    const title = escapeXml(cardData.personal?.title || '');
    const company = escapeXml(cardData.personal?.company || '');
    const fullName = `${firstName} ${lastName}`.trim();
    const description = title ? `${title} at ${company}` : company || 'Digital Business Card';

    // Construct preview image URL
    // Use short_code if available (globally unique), otherwise use the identifier
    const previewIdentifier = cardRow.short_code || cardIdentifier;
    const previewUrl = `${APP_URL}/api/cards/${previewIdentifier}/preview.png`;

    const metaTags = `
        <title>${fullName} - Digital Business Card</title>
        <meta name="description" content="${description}">
        <meta property="og:title" content="${fullName}">
        <meta property="og:description" content="${description}">
        <meta property="og:image" content="${previewUrl}">
        <meta property="og:image:width" content="1200">
        <meta property="og:image:height" content="630">
        <meta property="og:image:type" content="image/png">
        <meta property="og:type" content="profile">
        <meta name="twitter:card" content="summary_large_image">
        <meta name="twitter:title" content="${fullName}">
        <meta name="twitter:description" content="${description}">
        <meta name="twitter:image" content="${previewUrl}">
        <meta name="robots" content="index, follow">
      `;

    // Remove existing title tag to prevent duplicates
    html = html.replace(/<title>.*?<\/title>/i, '');

    return html.replace('</head>', metaTags + '</head>');
  } catch (err) {
    console.error('[Meta Tags] Error parsing card data:', err.message);
    return html; // Return unmodified on error
  }
}

// SPA Fallback - only for non-API and non-static routes
app.get('*', publicReadLimiter, async (req, res, next) => {
  // Don't serve index.html for static assets or API routes
  if (req.path.startsWith('/static/') || req.path.startsWith('/api/') || req.path.startsWith('/uploads/') || req.path.startsWith('/manifest/') || req.path.startsWith('/icons/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  try {
    // Read index.html from build directory
    const indexPath = path.join(__dirname, 'build', 'index.html');
    let html = await fs.promises.readFile(indexPath, 'utf8');

    // Try to detect card page and inject meta tags
    // Patterns:
    // 1. /{shortCode} - 7 alphanumeric characters (primary)
    // 2. /{orgSlug}/{cardSlug} - organization scoped
    // 3. /{slug} - legacy pattern (deprecated but still supported)

    const pathParts = req.path.slice(1).split('/').filter(p => p.length > 0);

    // Pattern 1: Short code (7 characters exactly)
    const isShortCode = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    if (isShortCode) {
      const shortCode = pathParts[0];
      html = await injectMetaTags(html, shortCode, shortCode);
    }
    // Pattern 2: Organization-scoped /{orgSlug}/{cardSlug}
    else if (pathParts.length === 2) {
      const [orgSlug, cardSlug] = pathParts;
      // Look up by org + card slug combination
      html = await injectMetaTags(html, cardSlug, `${orgSlug}/${cardSlug}`);
    }
    // Pattern 3: Legacy slug (anything that's not a short code and not org-scoped)
    else if (pathParts.length === 1) {
      const slug = pathParts[0];
      html = await injectMetaTags(html, slug, slug);
    }

    // Inject nonce into script tags (case-insensitive to catch all variants)
    html = html.replace(
      /<script(\s|>)/gi,
      `<script nonce="${res.locals.nonce}"$1`
    );

    // Replace %PUBLIC_URL% if needed (React build should already handle this, but be safe)
    html = html.replace(/%PUBLIC_URL%/g, '');

    // Set no-cache headers for index.html to ensure fresh content
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Content-Type': 'text/html; charset=utf-8'
    });

    res.send(html);
  } catch (err) {
    // If file doesn't exist or can't be read, return 404
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'Not found' });
    }
    next(err);
  }
});

// --- DEMO MODE FUNCTIONS ---

// Seed demo data for Demon Straight company
async function seedDemoData() {
  if (!IS_DEMO_MODE) return;

  try {
    log('[DEMO MODE] Seeding fresh demo data for Demon Straight...');

    // 0. Robustly delete all existing demo data (respecting foreign key constraints)
    // Delete in dependency order: child tables first, then parents

    // Delete all cards for demo users
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM cards WHERE user_id IN (SELECT id FROM users WHERE email LIKE ?)',
        ['%@demonstraight.com'],
        (err) => {
          if (err) {
            console.error('[DEMO MODE] Error deleting demo cards:', err.message);
            // Don't fail on this, could be first run
          }
          resolve();
        }
      );
    });

    // Delete all user settings for demo users
    await new Promise((resolve, reject) => {
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
    await new Promise((resolve, reject) => {
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
    await new Promise((resolve, reject) => {
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
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM organisations WHERE slug = ?',
        ['demon-straight'],
        (err) => {
          if (err) console.error('[DEMO MODE] Error deleting org:', err.message);
          resolve();
        }
      );
    });

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
    const { randomUUID } = require('crypto');
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
    DEMO_USER_ID = demoUserIds[0];
    log(`[DEMO MODE] Created 6 demo users with IDs: ${demoUserIds.join(',')}`);
    log(`[DEMO MODE] Demo owner user ID set to: ${DEMO_USER_ID}`);

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
      // This respects foreign key constraints by deleting in dependency order

      // Delete cards for demo users
      await new Promise((resolve) => {
        db.run(
          'DELETE FROM cards WHERE user_id IN (SELECT id FROM users WHERE email LIKE ?)',
          ['%@demonstraight.com'],
          (err) => {
            if (err) console.error('[DEMO MODE] Error deleting cards:', err.message);
            resolve();
          }
        );
      });

      // Delete user settings for demo users
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

      // Delete demo users
      await new Promise((resolve) => {
        db.run(
          'DELETE FROM users WHERE email LIKE ?',
          ['%@demonstraight.com'],
          (err) => {
            if (err) console.error('[DEMO MODE] Error deleting users:', err.message);
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

      // Delete demo organisation
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

      // Delete all uploaded files except demo images (those are preserved for next cycle)
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

// Run database migrations before starting the server
async function runMigrations() {
  try {
    console.log('Running database migrations...');
    // Use demo environment for demo mode, otherwise use dev
    const migrateEnv = IS_DEMO_MODE ? 'demo' : 'dev';
    execSync(`npx db-migrate up --env ${migrateEnv}`, {
      stdio: 'inherit',
      cwd: __dirname
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

// Run migrations and start server
// IMPORTANT: Wait for migrations to complete before accepting requests
// This ensures DEMO_USER_ID is set before auth middleware runs in demo mode
(async () => {
  try {
    await runMigrations();

    const server = app.listen(PORT, () => {
      // Startup logs are always useful, keep them
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${NODE_ENV}`);
      if (NODE_ENV === 'production') {
        console.log('HTTPS enforcement and security features enabled');
      }
    });

    // Graceful shutdown handler to close database connection
    function gracefulShutdown(signal) {
      console.log(`\n${signal} received. Closing database connection and shutting down gracefully...`);

      // Close database connection
      db.close((err) => {
        if (err) {
          console.error('Error closing database:', err.message);
        } else {
          console.log('Database connection closed.');
        }

        // Close server
        server.close(() => {
          console.log('Server closed.');
          process.exit(0);
        });

        // Force close after 10 seconds
        setTimeout(() => {
          console.error('Forced shutdown after timeout');
          process.exit(1);
        }, 10000);
      });
    }

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
})();
