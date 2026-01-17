#!/usr/bin/env node
/**
 * Capture Git information at build time
 * This script detects the current git branch and writes it to src/version.json
 * It's automatically run before build/start to ensure the app knows which branch it's on
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const outputPath = path.join(__dirname, '..', 'src', 'version.json');

function getGitBranch() {
  // Check if branch is provided via environment variable (useful for Docker/CI)
  if (process.env.GIT_BRANCH) {
    return process.env.GIT_BRANCH;
  }

  try {
    // Try to get the branch name from git
    const branch = execSync('git rev-parse --abbrev-ref HEAD', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
    return branch;
  } catch (error) {
    // Git not available or not a git repo, return null
    return null;
  }
}

function main() {
  const branch = getGitBranch();
  
  const versionInfo = {
    branch: branch,
    capturedAt: new Date().toISOString()
  };
  
  fs.writeFileSync(outputPath, JSON.stringify(versionInfo, null, 2));
  console.log(`Git info captured: branch=${branch || 'unknown'}`);
}

main();
