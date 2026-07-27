const { NODE_ENV } = require('../config/env');

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

module.exports = errorHandler;
