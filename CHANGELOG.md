# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

