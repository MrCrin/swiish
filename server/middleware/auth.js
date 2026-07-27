const jwt = require('jsonwebtoken');
const { db } = require('../db');
const { JWT_SECRET } = require('../config/env');
const { demoState } = require('../lib/demoMode');

// JWT Authentication middleware
const requireAuth = (req, res, next) => {
  // Demo mode: auto-authenticate as demo owner user
  if (demoState.isDemoMode && demoState.userId) {
    // Get demo user from database (using callback API since sqlite3 is async)
    db.get(
      'SELECT id, role, organisation_id FROM users WHERE id = ?',
      [demoState.userId],
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

module.exports = {
  requireAuth,
  requireRole,
};
