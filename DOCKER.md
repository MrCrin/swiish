# Swiish

**The Open-Source Digital Business Card Platform**

Swiish allows you to host your own digital business cards. Create beautiful profiles, generate QR codes for instant sharing, and let people save your contact details directly to their phones.

### Features
* 📱 **PWA Ready:** Install cards as native-like apps on mobile.
* 🔲 **QR Codes:** Auto-generated QR codes for every card.
* 🔒 **Privacy Controls:** Require interaction to reveal details or block bots.
* 🎨 **Theming:** Built-in dark mode and customization options.
* ⚡ **Lightweight:** Runs on a minimal Docker footprint.

---

### 🚀 Quick Start (Docker Compose)

The easiest way to run Swiish is with Docker Compose.

1. **Create a `docker-compose.yml` file:**

```yaml
services:
  swiish:
    image: ghcr.io/MrCrin/swiish:latest
    container_name: swiish
    restart: unless-stopped
    ports:
      - "8095:3000"
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
    environment:
      # --- REQUIRED ---
      - JWT_SECRET=change_this_to_a_long_random_string
      - ADMIN_PASSWORD=change_this_password
      
      # --- OPTIONAL (Production) ---
      - NODE_ENV=production
      - APP_URL=[https://cards.yourdomain.com](https://cards.yourdomain.com)
```

2. **Run it:**
```bash
docker compose up -d
```
3. **Access it:**
   Open `http://localhost:8095` in your browser. The application will guide you through the initial setup to create your organization and admin account.

---

### ⚙️ Configuration

You can configure Swiish using environment variables.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | **Required.** Random string for signing sessions. | *None* |
| `ADMIN_PASSWORD` | **Required.** Password for the initial admin account. | *None* |
| `ADMIN_EMAIL` | Email address for the default admin user. | `admin@localhost` |
| `APP_URL` | The public URL of your instance. Crucial for QR codes. | `http://localhost:8095` |
| `PORT` | Internal port the app listens on. | `3000` |
| `NODE_ENV` | Environment mode. | `development` |
| `JWT_EXPIRES_IN` | JWT token expiration time. | `24h` |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins. | `http://localhost:3000,http://localhost:8095` |
| `MAX_FILE_SIZE` | Max upload size in bytes. | `5242880` (5MB) |
| `FORCE_HTTPS` | Force HTTPS redirects. | `false` |

#### Email Configuration (Optional)
Required for sending invitations and password resets.

| Variable | Description |
| :--- | :--- |
| `SMTP_HOST` | Hostname of your SMTP provider. |
| `SMTP_PORT` | Port (e.g., 587 or 465). |
| `SMTP_USER` | SMTP Username. |
| `SMTP_PASSWORD` | SMTP Password. |
| `SMTP_FROM` | "From" address for emails. |

---

### 💾 Volumes

Persist these volumes to keep your data safe during updates:

* `/app/data`: Stores the SQLite database (`cards.db`).
* `/app/uploads`: Stores user-uploaded avatars and banners.

### 🔗 Links
* [Source Code on GitHub](https://github.com/MrCrin/swiish)
* [Report an Issue](https://github.com/MrCrin/swiish/issues)