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
| `.env.example` | Example env vars for deployment |  
| `CHANGELOG.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` | Version history, contribution guidelines, legal notices  |

---

## 📝 License

AGPL-3.0 - See [LICENSE](LICENSE) for full text and compliance requirements before pushing changes upstream to GitHub.
