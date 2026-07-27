const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { NODE_ENV, BUILD_DIR, UPLOADS_DIR } = require('./config/env');
const { cspDirectives, corsOptions } = require('./config/security');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth');
const uploadRoutes = require('./routes/uploads');
const cardRoutes = require('./routes/cards');
const settingsRoutes = require('./routes/settings');
const userRoutes = require('./routes/users');
const invitationRoutes = require('./routes/invitations');
const qrRoutes = require('./routes/qr');
const pwaRoutes = require('./routes/pwa');
const adminRoutes = require('./routes/admin');
const spaRoutes = require('./routes/spa');

const app = express();

// Trust proxy for rate limiting behind reverse proxy/load balancer
app.set('trust proxy', 1);

// --- MIDDLEWARE ---

// Generate nonce middleware (must be BEFORE helmet for CSP)
app.use((req, res, next) => {
  // Generate cryptographically random nonce for each request
  const nonce = require('crypto').randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  next();
});

// Security headers - configure CSP with connect-src for GitHub API
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
app.use(cors(corsOptions));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

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
app.use(express.static(BUILD_DIR, {
  maxAge: '1d', // Cache static assets for 1 day
  etag: true,
  lastModified: true,
  index: false // Don't automatically serve index.html - let SPA fallback handle it
}));
// Serve Uploaded Images publicly
app.use('/uploads', express.static(UPLOADS_DIR));

// --- API ROUTES ---
app.use(authRoutes);
app.use(uploadRoutes);
app.use(cardRoutes);
app.use(settingsRoutes);
app.use(userRoutes);
app.use(invitationRoutes);
app.use(qrRoutes);
app.use(pwaRoutes);
app.use(adminRoutes);

// Error handling middleware (must be registered before the SPA catch-all -
// Express only looks forward in the middleware stack for error handlers, so
// this order must match the original file's registration order exactly)
app.use(errorHandler);

// SPA Fallback - only for non-API and non-static routes (must be last)
app.use(spaRoutes);

module.exports = app;
