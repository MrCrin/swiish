# Swiish

</br><p align="left">
  <img src="https://raw.githubusercontent.com/MrCrin/swiish/master/public/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish Logo" width="200">
</p></br>

[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](https://github.com/MrCrin/swiish/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

**Open-source digital business card platform with QR codes and PWA support**

Swiish is a self-hostable platform for creating and sharing digital business cards. Create beautiful, customizable business cards with QR codes, share them via links, and let users save your contact information directly to their phones.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Development](#development)
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

## Quick Start

### Prerequisites

- **For Docker deployment**: Docker and Docker Compose
- **For local development**: Node.js 18+ and npm

### Installation

#### Option 1: Docker Deployment (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/MrCrin/swiish.git
   cd swiish
   ```

2. Set up environment:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

3. Start the application:
   ```bash
   docker-compose up -d
   ```

4. Access the application:
   - Main app: `http://localhost:8095`
   - Admin dashboard: `http://localhost:8095/admin`

#### Option 2: Manual Installation (For Development)

1. Clone and install dependencies:
   ```bash
   git clone https://github.com/MrCrin/swiish.git
   cd swiish
   npm install
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env
   ```

3. Start development server:
   ```bash
   npm start  # React dev server on http://localhost:3000
   ```

For production, build and serve:
   ```bash
   npm run build
   npm run serve  # Runs on PORT from .env, default 3000
   ```

## Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and fill in your values.

### Required Variables

- **`JWT_SECRET`** - Secret key for JWT token signing. Generate with: `openssl rand -base64 32`
- **`ADMIN_PASSWORD`** - Password for accessing the admin dashboard

### Optional Variables

- **`NODE_ENV`** - Environment mode (`development` or `production`)
- **`PORT`** - Server port (default: `3000`)
- **`APP_URL`** - Base URL for the application (required in production)
- **`ALLOWED_ORIGINS`** - Comma-separated list of allowed CORS origins
- **`MAX_FILE_SIZE`** - Maximum file upload size in bytes (default: 5MB)
- **`FORCE_HTTPS`** - Force HTTPS redirects (`true` or `false`)
- **Email Configuration (SMTP)** - For email features like invitations

See `.env.example` for all available options and their descriptions.

## Usage

### Creating Your First Card

1. Access the admin dashboard at `/admin`
2. Log in with your `ADMIN_PASSWORD`
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

## Development

### Local Development Setup

1. Clone and install:
   ```bash
   git clone https://github.com/MrCrin/swiish.git
   cd swiish
   npm install
   ```

2. Set up environment:
   ```bash
   cp .env.example .env
   # Configure for development
   ```

3. Start development server:
   ```bash
   npm run dev  # Runs build and server in watch mode
   ```

### Project Structure

```
swiish/
├── src/                    # React frontend
│   ├── App.js             # Main application
│   ├── index.js           # React entry point
│   └── theme/             # Theming system
├── public/                # Static assets
├── server.js              # Express backend
├── data/                  # SQLite database
├── uploads/               # User uploads
└── migrations/            # Database migrations
```

### Available Scripts

- `npm start` - Start React development server
- `npm run build` - Build production React app
- `npm run serve` - Serve production build
- `npm run dev` - Development mode with hot reload
- `npm run migrate` - Run database migrations

## Contributing

We welcome contributions!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add tests
4. Run the development server: `npm run dev`
5. Submit a pull request

## License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
