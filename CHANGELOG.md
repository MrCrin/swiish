# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Version badge now shows blue border when code is ahead of latest GitHub release (instead of red)
- Version comparison now follows SemVer precedence rules, properly handling pre-release versions (e.g., `0.2.2-dev` vs `0.2.1`)
- QR code share modal redesigned to full-screen overlay for better visibility
- QR code now displays at 90% width at the top of the screen (previously constrained to small modal)
- Share controls (Link only/Full details toggle and Close button) moved to bottom of screen
- Replaced "Share Card" heading with card name, company, and short URL display
- Removed backdrop blur from QR overlay for cleaner appearance
- Desktop overlay uses 22px border radius (2px smaller than card container) to prevent background bleed-through
- Banner/header opacity set to 0% when QR overlay is active to prevent underlying card background from showing through rounded corners

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

