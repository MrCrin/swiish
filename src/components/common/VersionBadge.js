import React, { useState, useEffect } from 'react';
import { APP_VERSION, GITHUB_URL, GIT_BRANCH } from '../../constants/app';

function VersionBadge() {
  const [isOutdated, setIsOutdated] = useState(false);
  const [isAhead, setIsAhead] = useState(false);
  const [isChecking, setIsChecking] = useState(true);

  // Determine if we're on a non-release branch
  // Show branch name if it's not main, master, or a version tag pattern (e.g., v0.3.1)
  const isReleaseBranch = !GIT_BRANCH ||
    GIT_BRANCH === 'main' ||
    GIT_BRANCH === 'master' ||
    /^v?\d+\.\d+/.test(GIT_BRANCH) ||
    GIT_BRANCH === 'HEAD'; // Detached HEAD state (common in CI/Docker)

  const showBranch = GIT_BRANCH && !isReleaseBranch;

  useEffect(() => {
    // Check GitHub for latest version
    const checkVersion = async () => {
      try {
        const response = await fetch('https://api.github.com/repos/MrCrin/swiish/releases/latest', {
          headers: {
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        if (response.ok) {
          const data = await response.json();
          const latestVersion = data.tag_name?.replace(/^v/, '') || data.tag_name; // Remove 'v' prefix if present
          const currentVersion = APP_VERSION;

          // SemVer-compliant version comparison
          // Follows SemVer precedence rules: pre-release versions have lower precedence than stable versions
          const compareVersions = (v1, v2) => {
            // Parse versions into base version and pre-release identifier
            const parseVersion = (version) => {
              const dashIndex = version.indexOf('-');
              if (dashIndex === -1) {
                return {
                  base: version,
                  prerelease: null
                };
              }
              return {
                base: version.substring(0, dashIndex),
                prerelease: version.substring(dashIndex + 1)
              };
            };

            const parsed1 = parseVersion(v1);
            const parsed2 = parseVersion(v2);

            // Compare base versions numerically
            const base1 = parsed1.base.split('.').map(Number);
            const base2 = parsed2.base.split('.').map(Number);

            for (let i = 0; i < Math.max(base1.length, base2.length); i++) {
              const part1 = base1[i] || 0;
              const part2 = base2[i] || 0;
              if (part1 < part2) return -1;
              if (part1 > part2) return 1;
            }

            // Base versions are equal, now check pre-release identifiers
            // Rule: A version without a pre-release identifier has higher precedence
            if (parsed1.prerelease === null && parsed2.prerelease === null) {
              return 0; // Both are stable, equal
            }
            if (parsed1.prerelease === null) {
              return 1; // v1 is stable, v2 is pre-release, v1 > v2
            }
            if (parsed2.prerelease === null) {
              return -1; // v1 is pre-release, v2 is stable, v1 < v2
            }

            // Both have pre-release identifiers, compare lexicographically
            const prerelease1 = parsed1.prerelease.split('.');
            const prerelease2 = parsed2.prerelease.split('.');

            for (let i = 0; i < Math.max(prerelease1.length, prerelease2.length); i++) {
              const part1 = prerelease1[i];
              const part2 = prerelease2[i];

              if (part1 === undefined) return -1; // v1 has fewer parts, v1 < v2
              if (part2 === undefined) return 1; // v2 has fewer parts, v1 > v2

              // Try numeric comparison first, fall back to string comparison
              const num1 = Number(part1);
              const num2 = Number(part2);

              if (!isNaN(num1) && !isNaN(num2)) {
                // Both are numeric
                if (num1 < num2) return -1;
                if (num1 > num2) return 1;
              } else {
                // At least one is non-numeric, compare as strings
                if (part1 < part2) return -1;
                if (part1 > part2) return 1;
              }
            }

            return 0; // Pre-release identifiers are equal
          };

          if (latestVersion) {
            const comparison = compareVersions(currentVersion, latestVersion);
            if (comparison < 0) {
              setIsOutdated(true);
            } else if (comparison > 0) {
              setIsAhead(true);
            }
          }
        }
      } catch (error) {
        console.error('Failed to check version:', error);
        // Silently fail - don't show error to user
      } finally {
        setIsChecking(false);
      }
    };

    checkVersion();
  }, []);

  // Build the display string: "v0.3.1" or "v0.3.1 (feature-branch)"
  const versionDisplay = showBranch
    ? `v${APP_VERSION} (${GIT_BRANCH})`
    : `v${APP_VERSION}`;

  // Build the tooltip
  const tooltip = (!isOutdated && !isAhead && !showBranch)
    ? "You are on the latest release"
    : (isAhead || showBranch)
      ? "You are on an unreleased development version - things may break"
      : isOutdated
        ? "Update available on GitHub"
        : "View on GitHub";

  return (
    <div className="fixed bottom-4 left-4 z-50">
      <a
        href={GITHUB_URL}
        target="_blank"
        rel="noopener noreferrer"
        className={`text-xs font-medium transition-all bg-card dark:bg-card-dark border-2 border-border dark:border-border-dark px-2 py-1 rounded shadow-sm hover:shadow-md ${
          showBranch
            ? 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20 hover:border-amber-300 dark:hover:border-amber-700'
            : isOutdated
              ? 'text-error-text dark:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark hover:border-error-border dark:hover:border-error-border-dark'
              : isAhead
                ? 'text-info-text dark:text-info-text-dark hover:bg-info-bg dark:hover:bg-info-bg-dark hover:border-info-border dark:hover:border-info-border-dark'
                : 'text-text-primary dark:text-text-primary-dark hover:text-action dark:hover:text-action-dark hover:border-success-border dark:hover:border-success-border-dark'
        }`}
        title={tooltip}
      >
        {versionDisplay}
      </a>
    </div>
  );
}

export default VersionBadge;
