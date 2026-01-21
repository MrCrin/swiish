# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-01-21

### Added
- **Docker Publishing**: Added GitHub Actions workflow for automated Docker image building and publishing to Docker Hub
- **Multi-Platform Docker Builds**: Added support for building Docker images for multiple architectures (AMD64 and ARM64)
- **Docker Hub Integration**: Enhanced Docker image tagging with version numbers and latest tags, plus automated Docker Hub description updates

### Technical
- GitHub Actions workflow configured for release triggers and manual dispatch
- QEMU and Docker Buildx setup for cross-platform builds
- Docker login using GitHub secrets for secure publishing

## [0.4.1] - 2026-01-20

### Performance
- **Database Indexes**: Added performance indexes on frequently queried columns to improve query speed

## [0.4.0] - 2026-01-18

### Added
- **Git Branch Detection**: Implemented automatic detection of the current Git branch during build and start processes.
- **Version Badge Enhancements**: The version badge now displays the active branch name when running on non-release branches (e.g., feature branches), with a distinct amber styling and informative tooltips.
- **Save Button Feedback**: Added visual feedback to the card editor save button, including a loading spinner during the save process and a success checkmark upon completion.
- **Assets**: Added `Swiish_Logo_DarkBg.svg` graphic for use in documentation and dark-themed environments.

### Changed
- **Build Process**: Integrated `capture-git-info` script into `prestart` and `prebuild` hooks to ensure version information is always up-to-date.
- **Docker Optimization**: Updated Dockerfile to include Git for branch detection and configured it to handle "dubious ownership" issues in containerized environments.
- **Editor Performance**: Refactored sortable link components in the editor for better performance and cleaner code structure.
- **User Experience**: Added a minimum delay to the save operation to ensure visual feedback is visible to the user even on fast connections.
- **Documentation**: Comprehensive README.md rewrite, significantly shortening the content while retaining all essential information and adding project badges and logo.

### Technical
- New `scripts/capture-git-info.js` utility for build-time metadata extraction.
- Improved Docker build stage to properly handle Git metadata while keeping the final image lean.

## [0.3.1] - 2026-01-07

### Security
- Upgraded `multer` from v1.4.5 to v2.0.1 to resolve a Denial of Service (DoS) vulnerability.

## [0.3.0] - 2026-01-05

### Fixed
- Added graceful shutdown handler to properly close database connection on server shutdown, preventing file lock issues on Windows when deleting cards.db
- Fixed profile picture not displaying in card preview when editing - avatar container was collapsing due to flex layout, added `min-h-32 flex-shrink-0` to prevent height collapse

### Changed
- Version badge now shows blue border when code is ahead of latest GitHub release (instead of red)
- Version comparison now follows SemVer precedence rules, properly handling pre-release versions (e.g., `0.2.2-dev` vs `0.2.1`)
- QR code share view completely redesigned with full-screen layout for better visibility
- QR code now displays at 90% width at the top of the screen (previously constrained to small modal)
- Share controls (Link only/Full details toggle and Close button) moved to bottom of screen
- Replaced "Share Card" heading with card name, company, and short URL display
- QR view now uses conditional rendering instead of overlay - completely replaces card view when active (fixes mobile scrolling issues and background bleed-through)
- Removed backdrop blur from QR view for cleaner appearance
- Desktop QR view uses minimum height container instead of full screen for better layout
- Logo positioning fixed in both QR and card views to consistently appear at bottom of screen
- Desktop spacing optimized: QR/details at top, controls/logo at bottom with minimal padding between
- Setup page footer styling updated: removed border, increased top padding, removed bottom padding

## [0.2.2] - 2026-01-03

### Security
- **Fixed critical path injection vulnerability**: Added `validateFilePath()` function to prevent path traversal attacks in file upload handler. All file deletion operations now validate paths to ensure they remain within the uploads directory.
- **Fixed biased cryptographic random number generation**: Updated `generateShortCode()` function to use rejection sampling instead of modulo operation, ensuring uniform distribution of short code characters and eliminating bias.
- **Fixed polynomial ReDoS vulnerability**: Refactored organization slug generation to use separate `replace()` calls instead of regex alternation pattern, preventing potential denial-of-service attacks from crafted input with many dashes.
- **Fixed case-insensitive script tag filtering**: Updated CSP nonce injection regex to be case-insensitive (`/gi` flag), ensuring all script tag variants (`<SCRIPT>`, `<Script>`, etc.) receive nonce attributes for proper Content Security Policy enforcement.
- **Added comprehensive rate limiting**: Implemented rate limiting on 23 routes that were previously unprotected:
  - Added `publicReadLimiter` (300 requests per 15 minutes) for public read endpoints
  - Added `cardReadLimiter` (200 requests per 15 minutes) for card read endpoints
  - Applied rate limiting to all card endpoints, invitation endpoints, email verification, manifest/icon endpoints, QR endpoints, and SPA fallback route

### Technical
- All code scanning alerts resolved (30 total: 4 path injection, 1 biased random, 1 ReDoS, 1 bad tag filter, 23 missing rate limiting)
- Security improvements maintain backward compatibility
- Rate limiting configured with appropriate limits for different endpoint types

## [0.2.1] - 2025-12-28

### Fixed
- Version badge now correctly displays version from package.json
- Docker deployment fixed: database.json and migrations/ now included in Docker image

### Changed
- Version management: APP_VERSION now automatically reads from package.json, eliminating need to update version in multiple places

## [0.2.0] - 2025-12-28

### Breaking Changes
- **Color system migration**: All existing theme colors with Tailwind gradients will be automatically converted to hex on load. Any custom Tailwind classes (gradient, button, link, text) stored in the database will be replaced with inline styles. Users upgrading may need to re-select colors if they had custom shades other than 600.

### Added
- Database migration system using `db-migrate` for schema management
- `database.json` configuration file for migration settings
- `migrations/` directory with initial schema migration
- `npm run migrate` script for manual migration execution
- Automatic migration execution on server startup

### Fixed
- Sand texture now only appears on main background, not on Preview box in settings page desktop mode

### Changed
- Database schema initialization refactored from hardcoded `db.serialize()` blocks to migration-based system
- Schema creation now uses proper migration files instead of inline SQL in `server.js`
- Data migration (short code backfill) separated from schema initialization
- Server now runs migrations automatically before starting, ensuring database is up-to-date
- Swiish logo positioning aligned across admin/people, settings, and card edit pages - now uses fixed positioning to align vertically with version badge
- Login page improvements: removed horizontal line above logo, adjusted logo margins to match box spacing, changed heading from "Admin Access" to "Login"
- **Color system completely refactored to hex-only architecture**: Removed all Tailwind class generation complexity, simplified color data structure to use inline styles exclusively. Both "Standard Colors" and "Custom Colours" modes now use hex values internally. Removed shade selector, always auto-generate complementary secondary colors for standard colors, allow manual secondary color selection for custom colours. UI simplified with cleaner labels and better preview examples showing text, links, buttons, and gradient effects.

### Technical
- All CREATE TABLE and CREATE INDEX statements now use `IF NOT EXISTS` for safe, idempotent migrations
- Migration system is compatible with Docker deployments and persistent volumes
- Existing databases are safely migrated without data loss

## [0.1.2] - 2025-12-27

### Fixed
- Phone country selector flag icons now display correctly (was showing broken images)
- View button on admin page now has proper contrast (changed to match edit button styling)
- Content Security Policy updated to allow GitHub API calls for version checking

### Added
- Automatic design token annotation system - adds `data-theme-*` attributes to all elements for easier theming in Chrome DevTools
- Version badge hover indicators - green border on hover when up-to-date, red border when update available
- Country flag icons support via `country-flag-icons` package

### Changed
- Version badge styling improved with colored hover borders for better visual feedback

## [0.1.1] - 2025-12-24

### Fixed
- Service worker registration logic improved for better production build detection
- Icon generation now uses correct organization's theme colors instead of default organization
- SVG icon path updated to match actual Swiish_Logo_Device.svg file dimensions
- Horizontal scroll overflow issue fixed with CSS updates

### Changed
- PWA manifest icons updated to use SVG files from `/graphics/` directory
- Manifest and icon endpoints now support short codes (case-sensitive lookup)
- Improved responsive design for admin dashboard buttons (mobile-friendly sizing)
- Enhanced PWA install functionality with better error handling and browser-specific instructions

### Added
- Version badge component that displays current version and checks GitHub for updates
- Better error messages for PWA installation failures
- Manual installation instructions for different browsers when auto-install isn't available

### Removed
- Debug console.log statements from PWA manifest loading code

## [0.1.0] - 2025-12-20

### Added
- Initial release of Swiish
- Digital business card creation and management
- QR code generation (simple URL and vCard formats)
- Progressive Web App (PWA) support with offline capabilities
- Admin dashboard for card management
- Privacy controls (require interaction, obfuscation, block robots)
- Theme customization (pre-built Tailwind themes and custom hex colors)
- File upload support for avatars and banner images
- Dark mode support (automatic and manual toggle)
- Responsive design for desktop, tablet, and mobile
- Docker support with docker-compose for easy deployment
- JWT-based authentication
- CSRF protection
- Rate limiting
- Input validation and sanitization
- Security headers via Helmet
- SQLite database for data storage

### Security
- JWT-based authentication with httpOnly cookies
- XSS protection with DOMPurify
- CSRF token validation
- Rate limiting on sensitive endpoints
- Secure file upload validation (MIME type checking)
- Security headers via Helmet middleware
- Input validation and sanitization

