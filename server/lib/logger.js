const fs = require('fs');
const path = require('path');
const { PROJECT_ROOT, NODE_ENV, MAX_LOG_LINES } = require('../config/env');

const logFile = path.join(PROJECT_ROOT, 'server.log');
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

// `logLines` is reassigned (not mutated in place) by the trim above, so
// consumers must go through these accessors rather than destructuring the array.
function getRecentLogs(n) {
  return logLines.slice(-n);
}

function getLogCount() {
  return logLines.length;
}

module.exports = {
  log,
  getRecentLogs,
  getLogCount,
};
