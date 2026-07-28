const API_ENDPOINT = '/api';
const APP_VERSION = require('../../package.json').version; // Automatically read from package.json
const GITHUB_URL = 'https://github.com/MrCrin/swiish';

// Try to read branch info from active-branch.json (generated at build time)
let GIT_BRANCH = null;
try {
  const branchInfo = require('../active-branch.json');
  GIT_BRANCH = branchInfo.branch;
} catch (e) {
  // active-branch.json doesn't exist yet (first run before build)
  GIT_BRANCH = null;
}

export { API_ENDPOINT, APP_VERSION, GITHUB_URL, GIT_BRANCH };
