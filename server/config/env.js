require('dotenv').config();
const path = require('path');

// server/config/env.js lives two levels below the project root (server/config -> server -> root)
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

const NODE_ENV = process.env.NODE_ENV || 'development';

// Trust proxy for rate limiting behind reverse proxy/load balancer is set on `app` in app.js

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

const PORT = process.env.PORT || 3000;

// Short code configuration
const SHORT_CODE_LENGTH = 7;
const SHORT_CODE_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

// Upload configuration
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024; // 5MB default

// Logging configuration
const MAX_LOG_LINES = 1000;

const DATA_DIR = path.join(PROJECT_ROOT, 'data');
const UPLOADS_DIR = path.join(PROJECT_ROOT, 'uploads');
const BUILD_DIR = path.join(PROJECT_ROOT, 'build');
const PUBLIC_DIR = path.join(PROJECT_ROOT, 'public');

const fs = require('fs');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

module.exports = {
  PROJECT_ROOT,
  NODE_ENV,
  PORT,
  JWT_SECRET,
  JWT_EXPIRES_IN,
  ALLOWED_ORIGINS,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASSWORD,
  SMTP_FROM,
  APP_URL,
  IS_DEMO_MODE,
  SHORT_CODE_LENGTH,
  SHORT_CODE_CHARS,
  MAX_FILE_SIZE,
  MAX_LOG_LINES,
  DATA_DIR,
  UPLOADS_DIR,
  BUILD_DIR,
  PUBLIC_DIR,
};
