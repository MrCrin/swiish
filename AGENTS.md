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
|-------|------|
| **Frontend** | React 18.2, react-router-dom v6+, lucide-react icons, Tailwind CSS |
| **Backend** | Node.js/Express 4.x, SQLite3 + db-migrate ORM, nodemon hot-reload |
| **Build** | react-scripts (Webpack), concurrently for parallel watch processes |

## 📁 Structure

```
swiish/
├── src/              # React frontend components & entry points  
│   ├── App.js       → Main component: route-based rendering
│   ├── index.js     → ReactDOM.render + CSS import
│   └── components/  ↓ Common UI, editor, public-card views
├── server/           # Express API routes, middleware, services
├── migrations/       # db-migrate versioned schema files (SQL)  
├── public/          # Static assets served at "/" path + PWA manifest/SW
├── fonts/           # Atkinson Hyperlegible OTFs for card readability
└── server.js        → Express app entry point
```

## 🔐 Environment Variables (`.env`)

### Required

| Variable | Example | Purpose |
|----------|---------|---------|
| `JWT_SECRET` | `$(openssl rand -base64 32)` | JWT token signing key |

### Optional  

| Variable | Default | Purpose |
|----------|---------|---------|
| `NODE_ENV` | `development` | Run mode (webpack optimization) |
| `PORT` | `3000` | Express server listen port |
| `APP_URL` | — *required in prod* | Base URL / domain for app |
| `DEMO_MODE` | `false` | Enable demo data, skip login |
| `MAX_FILE_SIZE` | `5242880` (5MB) | Upload limit bytes |
| `FORCE_HTTPS` | — *blank = off* | Force HTTPS redirects in prod |
| `ALLOWED_ORIGINS` | `localhost:3000,8095` | CORS origins list |
| `JWT_EXPIRES_IN` | `24h` | JWT token lifetime |

### Email (SMTP - optional)

- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`  
- `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`  

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
|-------|-------------|
| Dev server won't start after code changes | `rm -rf node_modules && npm install` (node cache) |
| `/c/{token}` shows 404 SPA instead of card data | Run migrations first: `npm run migrate`; check logs for errors |  
| "no pending migration" but DB looks wrong | Verify working dir is repo root; ensure `.env→database.json` points to valid SQLite file |  
| CORS issues post-deployment | Check FORCE_HTTPS + APP_URL domain config in security.js  |

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
| `DOCKER.md` | Docker deployment setup |
| `.env.example` | All env var options documented here |  
| `CHANGELOG.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` | Version history, contribution guidelines, legal notices  |

---

## 📝 License

AGPL-3.0 - See [LICENSE](LICENSE) for full text and compliance requirements before pushing changes upstream to GitHub.
