# Swiish

</br><p align="left">
  <img src="https://raw.githubusercontent.com/MrCrin/swiish/master/public/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish Logo" width="200">
</p></br>

[![Version](https://img.shields.io/badge/version-0.6.0-blue.svg)](https://github.com/MrCrin/swiish/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Docker Image](https://github.com/MrCrin/swiish/actions/workflows/build_docker_on_release.yml/badge.svg)](https://github.com/MrCrin/swiish/actions/workflows/build_docker_on_release.yml)

**Open-source digital business card platform with QR codes and PWA support**

Swiish is a self-hostable platform for creating and sharing digital business cards. Create beautiful, customizable business cards with QR codes, share them via links, and let users save your contact information directly to their phones.

## Table of Contents

- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Changelog](#changelog)

## Features

- 📇 **Create and manage digital business cards** - Build professional digital cards with all your contact information
- 🎨 **Advanced theming engine** - Fully customizable design system with multiple theme variants, design token system, background textures, and automatic light/dark mode support
- 📱 **Progressive Web App (PWA)** - Install cards as apps on mobile devices for offline access
- 🔲 **QR code generation** - Generate QR codes with simple URLs or full vCard contact information
- 🔒 **Privacy controls** - Require interaction before revealing contact details, obfuscate contact info, and block search engines
- 📤 **File uploads** - Upload custom avatars and banner images
- 🌙 **Dark mode support** - Automatic dark mode with manual toggle
- 📱 **Responsive design** - Works beautifully on desktop, tablet, and mobile
- 🔐 **Admin dashboard** - Manage all your cards, users, and organization settings from a central dashboard

## Demo

Have a look at a working demo:

- How your cards can look
    - <https://swiish-demo.up.railway.app/LINES02>
    - <https://swiish-demo.up.railway.app/LEVEL03>
    - <https://swiish-demo.up.railway.app/PLUMB05>
- How the admin dashboard looks (demo will bypass login)
    - <https://swiish-demo.up.railway.app/>

**Note**: The demo is reset hourly and doesn't include the setup process that runs when you first install Swiish.

## Installation

**Prerequisites:** Docker Compose

1. Download [docker-compose.yml](docker-compose.yml) and modify volume mounts to your liking.
2. Download [.env.example](.env.example) and rename it `.env`
3. Configure `.env` to your liking
4. Run `docker compose up -d`.

### Development

See [CONTRIBUTING.md](CONTRIBUTING.md#local-setup) for instructions.

## Configuration

Configuration is done via environment variables. Copy `.env.example` to `.env` and fill in your values.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | **Required.** Random string for signing sessions. | *None* |
| `APP_URL` | The public URL of your instance. Crucial for QR codes. | `http://localhost:8095` |
| `PORT` | Internal port the app listens on. | `3000` |
| `NODE_ENV` | Environment mode. | `development` |
| `DEMO_MODE` | Disables auth and uses demo data. | `false` |
| `JWT_EXPIRES_IN` | JWT token expiration time. | `24h` |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins. | `http://localhost:3000,http://localhost:8095` |
| `MAX_FILE_SIZE` | Max upload size in bytes. | `5242880` (5 MiB) |
| `FORCE_HTTPS` | Force HTTPS redirects. | `false` |
| `SMTP_HOST` | Hostname of your SMTP provider. | *None* |
| `SMTP_PORT` | Port (e.g., 587 or 465). | *None* |
| `SMTP_USER` | SMTP Username. | *None* |
| `SMTP_PASSWORD` | SMTP Password. | *None* |
| `SMTP_FROM` | "From" address for emails. | *None* |

See `.env.example` for all available options and their descriptions.

### Demo Mode (Experimental)

Demo mode allows visitors to explore Swiish without requiring authentication or setup. This is useful for showcasing the platform on dedicated demo instances.

#### Enabling Demo Mode

1. Set the `DEMO_MODE` environment variable to `true`
2. Restart the server
3. The app will automatically:
   - Seed the database with demo company "Demon Straight" (a fictional company that makes really straight things)
   - Create 6 demo employees with different card configurations
   - Skip the login flow and auto-authenticate visitors
   - Reset all data every hour to maintain a clean demo state

## Usage

### Creating Your First Card

1. Complete the initial setup wizard at `/setup` to create your organization and admin account
2. Log in to access the admin dashboard at `/admin`
3. Click "Create New Card"
4. Enter a unique slug (e.g., `john-doe`)
5. Fill in your contact information, upload images, customize the theme
6. Click "Save"
7. Your card is now available at `http://your-domain.com/john-doe`

### Sharing Cards

- **Direct Link**: Share the card URL directly
- **QR Code**: Click the share button on any card to generate a QR code
    - **Simple Mode**: QR code contains just the card URL
    - **Full Details Mode**: QR code contains vCard data for direct contact saving

### Privacy Controls

Each card supports three privacy options:

- **Require Interaction**: Users must click "See my details" before contact info is revealed
- **Client-Side Obfuscation**: Contact information is obfuscated in the HTML
- **Block Robots**: Prevents search engines from indexing the card

### Theme Customization

Swiish features a powerful theming engine with design tokens for colors, textures, border radius, and border width. Built-in themes include "swiish" and "minimal". You can create custom themes by adding files to `src/theme/`.

For detailed theming instructions, see the [full documentation](https://github.com/MrCrin/swiish/wiki/Theming).

## Contributing

We welcome contributions! Check out [CONTRIBUTING.md](CONTRIBUTING.md)!

## License

This project is licensed under the AGPL-3.0 License with a Trademark exception. For more information, see the [LICENSE.md](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
