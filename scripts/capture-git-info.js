#!/usr/bin/env node
/**
 * Capture Git information at build time
 * This script detects the current git branch and writes it to src/version.json
 * It's automatically run before build/start to ensure the app knows which branch it's on
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const outputPath = path.join(__dirname, '..', 'src', 'active-branch.json');

function getGitBranch() {
  console.log('Attempting to detect Git branch...');
  
  // 1. Try to get the branch name from git first (if .git folder is present)
  try {
    // Fix for "dubious ownership" in Docker/CI environments
    try {
      execSync('git config --global --add safe.directory /app', { stdio: 'ignore' });
    } catch (e) {
      // Ignore errors setting safe directory
    }

    // Try multiple ways to get the branch name
    let branch = null;
    
    // Method A: git branch --show-current (Modern git)
    try {
      branch = execSync('git branch --show-current', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
    } catch (e) {}

    // Method B: git rev-parse --abbrev-ref HEAD (Legacy/Fallback)
    if (!branch || branch === '') {
      try {
        branch = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
      } catch (e) {}
    }
    
    console.log(`Git command returned: "${branch || 'null'}"`);
    
    // If we got a valid branch (not HEAD), return it
    if (branch && branch !== 'HEAD' && branch !== '') {
      return branch;
    }
  } catch (error) {
    console.log(`Git detection failed: ${error.message}`);
  }

  // 2. Fallback to environment variable (useful for CI/Docker where .git might be missing)
  if (process.env.GIT_BRANCH) {
    console.log(`Using GIT_BRANCH env var: "${process.env.GIT_BRANCH}"`);
    return process.env.GIT_BRANCH;
  }

  console.log('No branch detected.');
  return null;
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
