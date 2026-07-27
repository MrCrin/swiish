const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const { apiLimiter } = require('../config/security');
const { getRecentLogs, getLogCount } = require('../lib/logger');

const router = express.Router();

// Admin endpoint to view logs
// NOTE: fixed to require the 'owner' role, matching every other /api/admin/* route -
// previously this only required requireAuth, so any authenticated user (not just
// owners) could read server logs.
router.get('/api/admin/logs', requireAuth, requireRole('owner'), apiLimiter, (req, res, next) => {
  try {
    // Return last 100 lines
    const recentLogs = getRecentLogs(100);
    res.json({ logs: recentLogs, totalLines: getLogCount() });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
