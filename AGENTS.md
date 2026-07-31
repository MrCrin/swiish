# Swiish - Digital Business Card Platform (Open Source AGPL-3.0)

## 🎯 Overview

Self-hostable PWA for creating digital business cards with QR codes and privacy controls. Share contacts via links or scan-to-save without app installation.

### Features

- Create/edit/delete contact cards with custom branding
- Generate unique public URLs (with optional expiration)
- QR code support for offline sharing
- Privacy: PIN protection, password expiry settings  
- Multi-profile admin dashboard (invite-based user creation)
- Demo mode for showcasing platform without auth

## 🛠 Stack

| Layer | Tech |
| ------- | ------ |
| **Frontend** | React 18.2, react-router-dom v6+, lucide-react icons, Tailwind CSS |
| **Backend** | Node.js/Express 4.x, SQLite3 + db-migrate ORM, nodemon hot-reload |
| **Build** | react-scripts (Webpack), concurrently for parallel watch processes |

## 📁 Structure

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

## 🔐 Environment Variables (`.env`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | **Required.** Random string for signing sessions. | *None* |
| `APP_URL` | The public URL of your instance. Crucial for QR codes. | `http://localhost:8095` |
| `PORT` | Internal port the app listens on. | `3000` |
| `NODE_ENV` | Environment mode. | `development` |
| `JWT_EXPIRES_IN` | JWT token expiration time. | `24h` |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins. | `http://localhost:3000,http://localhost:8095` |
| `MAX_FILE_SIZE` | Max upload size in bytes. | `5242880` (5 MiB) |
| `FORCE_HTTPS` | Force HTTPS redirects. | `false` |
| `SMTP_HOST` | Hostname of your SMTP provider. | *None* |
| `SMTP_PORT` | Port (e.g., 587 or 465). | *None* |
| `SMTP_USER` | SMTP Username. | *None* |
| `SMTP_PASSWORD` | SMTP Password. | *None* |
| `SMTP_FROM` | "From" address for emails. | *None* |

---

## 🚀 Development Commands

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

Note: Remind the user to format markdown files using the workspace recommended VSCode extensions.

---

## 🔧 Deployment Checklist

- **Database**: `database.json` → SQLite path; writable location with persistent backing
- **HTTPS in prod**: Set `FORCE_HTTPS=true`, use nginx/caddy/traefik reverse proxy
- **CORS** (`server/config/security.js`): Match origins to APP_URL domain if different  

---

## 🔍 Troubleshooting  

| Issue | Cause → Fix |
| ------- | ------------- |
| Dev server won't start after code changes | `rm -rf node_modules && npm install` (node cache) |
| `/c/{token}` shows 404 SPA instead of card data | Run migrations first: `npm run migrate`; check logs for errors |  
| "no pending migration" but DB looks wrong | Verify working dir is repo root; ensure `.env→database.json` points to valid SQLite file |  
| CORS issues post-deployment | Check FORCE_HTTPS + APP_URL domain config in security.js |

---

## 🔒 Security Notes

- Passwords hashed with bcrypt before login check (`server/middleware/auth.js`)  
- File uploads sanitized (DOMPurify) - see `src/utils/sanitize.js`  
- Helmet, rate-limiting enabled; adjust CORS origins per environment  

---

## 📄 Additional Docs

| File | Purpose |
|------|---------|
| `README.md` | Installation / quickstart / GitHub copy |
| `.env.example` | Example env vars for deployment |  
| `CHANGELOG.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` | Version history, contribution guidelines, legal notices  |

---

## 📝 License

AGPL-3.0 - See [LICENSE](LICENSE) for full text and compliance requirements before pushing changes upstream to GitHub.
