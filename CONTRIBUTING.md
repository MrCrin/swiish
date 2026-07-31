# Contributing

Firstly, thank you for considering contributing to Swiish. This started as a personal learning project to create something I wanted and needed and has grown into a project that I hope others will find useful.

Swiish is an open-source, self-hostable platform for digital business cards. My goal is to provide a professional, privacy-focused, and offline-tolerant solution for sharing your details while networking, both in person and digitally.

## Code of Conduct

To ensure that Swiish is a welcoming and inclusive project for everyone. By participating, you agree to:

* Be respectful and kind to others.
* Use welcoming and inclusive language.
* Be collaborative and open to feedback.
* Gracefully accept constructive criticism.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please open an issue on GitHub. Include as much detail as possible:

* Use the template provided.
* A clear, descriptive title.
* Steps to reproduce the bug.
* What you expected to happen vs. what actually happened.
* Screenshots or screen recordings if applicable.
* Your environment (Browser, OS, Swiish version).

### Suggesting Features

We love ideas. If you have a feature request:

* Use the template provided.
* Check if the feature has already been suggested.
* Open an issue and describe the feature, why it's useful, and how it might work.

### Improving Documentation

Documentation is easily as important as code - and for the user more so. If you see a typo, a confusing section, or something missing in the README or other docs, feel free to submit an issue or fix it and submit a PR.

## Development Workflow

### Branching Strategy

We use a `develop` branch model to keep the `master` branch stable while allowing for continuous development.

1. **Master Branch**: Represents the latest stable, production-ready release.
2. **Develop Branch**: The main integration branch for development. All new features and bug fixes should target this branch.
3. **Feature Branches**: Create your feature or bugfix branch off the **`develop` branch**.
    * Naming convention: `feature/your-feature-name` or `fix/your-fix-name`.
4. **Pull Requests**: Submit your PR into the **`develop` branch**.
5. **Releases**: When we are ready for a new release, the `develop` branch is merged into `master` and tagged with a version number (e.g., `v0.5.0`).

### Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) to keep our history clean and automate changelogs. Please format your commit messages as follows:

* `feat: add new theme support`
* `fix: resolve alignment issue on mobile`
* `docs: update contributing guidelines`
* `style: fix linting errors`
* `refactor: simplify card rendering logic`

You can also include a commit body with more details if needed - but don't feel obliged, just if it's helpful to 'future you' or others.

## Local Setup

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/your-username/swiish.git`
3. Enter the directory: `cd swiish`

### Building and Testing Changes

#### Bare Metal

1. Install dependencies: `npm install`
2. Set up your environment: `cp .env.dev .env`  
(see [README.md](README.md#configuration) for env variables)
3. Run the development server: `npm run dev`

Useful Commands:

```bash
# Full dev server: frontend + backend watch mode 
npm run dev

# Frontend only (localhost:3000) - no backend needed in some setups
npm start

# Production build and serve  
npm run build && npm run serve  # Listens on PORT from .env or :3000 default

# Database migrations before starting app  
npm run migrate

# Delete all local data from dev environment
npm run clean-data
```

Full list of `npm run` commands is under scripts in [package.json](package.json).

#### Docker

Run the container: `npm run docker`

Reset the development data: `npm run clean-data`

Rebuild and run the development container from the current environment: `npm run docker:update`

## Pull Request Process

1. Ensure your code follows the existing style.
2. Update the documentation if you're adding or changing features.
3. Make sure your PR title follows Conventional Commits.
4. Provide a clear description of the changes in the PR body.
5. Wait for a review.

## Project Structure

Copied from [AGENTS.md](AGENTS.md#-structure)

```
swiish/
├── src/ # React frontend components & entry points
│ ├── App.js → Main component: route-based rendering with react-router-dom
│ ├── index.js → ReactDOM.createRoot + CSS imports (index.css)
│ ├── components/ ↓ Feature modules organized by domain
│ │ ├── common/ → Reusable UI primitives (Input, Modal, Toggle, ColorSelector...)
│ │ ├── editor/ → Card editing interface with sortable links
│ │ ├── invitations/ → Invitation acceptance UI
│ │ ├── public-card/ → Generated contact card displays
│ │ ├── settings/ → Platform configuration panel
│ │ └── users/ → User management & invitation flows
│ ├── constants/ → Shared constants: app config, color palettes, icon mappings
│ ├── theme/ → Theme definitions (minimal.js, swiish.js)
│ └── utils/ → Helper functions: card templates, QR encoding, sanitization
├── server/ # Express backend: routes, middleware, services, utilities
│ ├── index.js → App startup: migrations first, then HTTP listener with graceful shutdown
│ ├── app.js → Central router composition; Helmet/CORS/security headers, middleware chain
│ └── [subdirectories]/ ↓ Organized by concern
│ ├── config/ → env.js (environment variables), security.js (CSP, corsOptions)
│ ├── db/ → Database connection pool, migration runner (db-migrate)
│ ├── lib/ → Utility modules: audit logging, demo mode checker, mailer, QR encoding, paths, tokens
│ ├── middleware/ → auth.js (JWT verification + bcrypt), validation.js (AJV schemas + csurf), errorHandler
│ ├── routes/ ↓ API endpoints grouped by resource (prefixed with /api)
│ │ ├── admin → Admin dashboard operations
│ │ ├── auth → Authentication (login, register)
│ │ ├── cards → Contact card CRUD + public URL generation (/c/{token})
│ │ ├── invitations → Invitation management
│ │ ├── pwa → Service worker registration & PWA assets
│ │ ├── qr → QR code generation endpoints
│ │ ├── settings → Platform-wide settings
│ │ ├── spa → SPA fallback routing
│ │ └── uploads → File upload handling (multer) + public static serving
│ └── services/ ↓ Business logic layers (extracted from routes)
│ ├── cardService.js → Card data operations
│ └── settingsService.js → Settings data operations
├── migrations/ # db-migrate versioned schema files
│ ├── 2025MMDDHHMMSS-description.js → Migration wrapper with .up()/.down() lifecycle
│ └── sqls/ ↓ Raw SQL for each migration step (up/down pairs)
├── public/ # Static assets served at "/" path + PWA support
│ ├── index.html → SPA entry point (React Router mounts here)
│ ├── manifest.json → PWA manifest for installability
│ ├── service-worker.js → Offline caching strategy for card assets
│ └── demo/ ↓ Placeholder assets for testing UI without uploads
│ ├── demo/avatar-*.jpg → Placeholder avatars
│ └── demo/banner-*.jpg → Placeholder banners
├── scripts/ # Build-time utilities (Node.js scripts)
│ ├── capture-git-info.js → Embeds git commit hash in build metadata
│ └── test-preview-security.js → Validates DOMPurify sanitization on uploaded previews
├── data/ → SQLite database file (writable, persistent storage)
├── uploads/ → Temporary file storage for user-uploaded images
├── fonts/ → Atkinson Hyperlegible typeface for card text rendering
│ ├── AtkinsonHyperlegible-Bold.otf → Headlines, emphasis text
│ └── AtkinsonHyperlegible-Regular.otf → Body content via @font-face
├── nodemon.json → Nodemon config: watch server/, auto-restart on changes
├── docker-compose.*.yml → Container orchestration: dev/prod stacks + nginx proxy
├── .env.dev → Default environment file for local development
├── .env.example → Template for required environment variables
├── .env → Working copy of .env.dev that takes effect on dev instances; NEVER commit to VCS
└── .gitignore → Git ignore patterns for junk/temp files (data/, uploads/, .env)
```

## Coding Standards

| Layer | Guidelines |
| ------- | ------------ |
| **Frontend** | Components live under `src/components/` organized by feature (e.g., `/editor/`, `/public-card/`). Keep each component focused and reuse common UI primitives from [`src/components/common/`](src/components/common). Routes are defined in [`src/App.js`](src/App.js) using react-router-dom. |
| **Styling** | Use Tailwind CSS utility classes for all styling. Refer to [`tailwind.config.js`](tailwind.config.js) for available config (colors, fonts like Atkinson Hyperlegible). |
| **Backend** | Routes and middleware are in `server/routes/` and `server/middleware/`. Business logic lives in `server/services/`. Entry point is [`server/index.js`](server/index.js) with configuration in `server/config/`. Keep concerns separated as the codebase grows. |
| **Database** | Schema changes go through versioned migrations under `migrations/` (run via `npm run migrate`). See existing migration files for naming conventions and format. |

## Future: Testing

We don't have a comprehensive test suite yet, but we're looking to add one. If you're interested in helping set up a testing framework (like Vitest or Jest), please open an issue to discuss!

---

Thank you for helping make Swiish better!
