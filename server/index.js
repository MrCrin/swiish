const { PORT, NODE_ENV } = require('./config/env');
const { db } = require('./db');
const { runMigrations } = require('./db/migrate');
const app = require('./app');

// Run migrations and start server
// IMPORTANT: Wait for migrations to complete before accepting requests
// This ensures the demo user id is set before auth middleware runs in demo mode
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
