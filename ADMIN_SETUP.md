# PhishGuard Admin Panel — Setup Guide

## Overview

The admin panel is a fully integrated, session-authenticated dashboard that runs alongside your existing PhishGuard app. No extra server or database is needed — it reads from the same MongoDB instance.

---

## 🗂️ New Files Added

| File | Purpose |
|---|---|
| `admin_routes.py` | All admin API routes & auth logic (Flask Blueprint) |
| `admin_panel.html` | Full single-page admin dashboard (HTML/CSS/JS) |
| `admin_login.html` | Secure admin login page |
| `admin.env.example` | Environment variable template |
| `ADMIN_SETUP.md` | This file |

---

## ⚡ Quick Start

### 1. Add environment variables to `apikey.env`

```env
FLASK_SECRET_KEY=<generate a random 32-byte hex string>
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<sha256 hash — see below>
```

#### Generating a password hash

```python
import hashlib
salt = 'phishguard_salt_2024'        # default salt
pw   = 'YourNewStrongPassword'
print(hashlib.sha256(f'{pw}{salt}'.encode()).hexdigest())
```

Copy the output into `ADMIN_PASSWORD_HASH=`.

> **Default credentials (development only):**
> - Username: `admin`
> - Password: `admin123`
> - **Change these before deploying!**

---

### 2. No code changes required in `app.py` beyond what is already done

The admin Blueprint is already registered. Just restart the server.

---

### 3. Access the panel

```
http://localhost:5000/admin/login
http://localhost:5000/admin/dashboard
```

---

## 🔐 Security Details

### Authentication
- Password is **SHA-256 hashed** with a configurable salt — never stored in plaintext.
- Sessions are **server-side** via Flask's signed cookie session (requires `FLASK_SECRET_KEY`).
- Sessions expire after **8 hours** of inactivity.
- All admin API routes return `401` and redirect to `/admin/login` if unauthenticated.

### Session Hardening
- `SESSION_COOKIE_HTTPONLY = True` — prevents JS access to the cookie.
- `SESSION_COOKIE_SAMESITE = 'Lax'` — CSRF protection.
- Set `SESSION_COOKIE_SECURE = True` in production (HTTPS only).

### Changing the salt
Override the default salt in your `.env`:
```
ADMIN_SALT=your_custom_salt_string
```
Then re-generate and update `ADMIN_PASSWORD_HASH` accordingly.

---

## 📋 Admin Panel Features

| # | Feature | Route |
|---|---|---|
| 1 | **Admin Authentication** | `POST /admin/api/login`, `POST /admin/api/logout` |
| 2 | **Dashboard Overview** | `GET /admin/api/dashboard` |
| 3 | **URL Scan History** | `GET /admin/api/scans` (search, filter, paginate) |
| 4 | **Detailed Scan View** | `GET /admin/api/scans/<id>` |
| 5 | **Domain Reputation** | `GET /admin/api/domains` |
| 6 | **User Reports** | `GET /admin/api/reports` |
| 7 | **Screenshot Monitoring** | `GET /admin/api/screenshots` |
| 8 | **System Health** | `GET /admin/api/health` |
| 9 | **Analytics** | `GET /admin/api/analytics?days=7|14|30` |
| 10 | **Activity Logs** | `GET /admin/api/logs` |
| — | **CSV Export** | `GET /admin/api/export/scans` |

---

## 🌐 URL Structure

```
/admin/login              → Login page
/admin/dashboard          → Admin SPA (all panels)
/admin/api/login          → POST — authenticate
/admin/api/logout         → POST — end session
/admin/api/me             → GET  — check session
/admin/api/dashboard      → GET  — summary stats + recent activity
/admin/api/scans          → GET  — scan history (pagination + filters)
/admin/api/scans/<id>     → GET  — full scan detail
/admin/api/domains        → GET  — domain reputation table
/admin/api/reports        → GET  — community reports
/admin/api/screenshots    → GET  — screenshot index
/admin/api/health         → GET  — system health
/admin/api/analytics      → GET  — charts data
/admin/api/logs           → GET  — admin activity logs
/admin/api/export/scans   → GET  — CSV download
```

---

## 🚀 Production Checklist

- [ ] Set a strong `FLASK_SECRET_KEY` (32+ random bytes)
- [ ] Set a strong `ADMIN_USERNAME` (not "admin")
- [ ] Change `ADMIN_PASSWORD_HASH` to a strong password hash
- [ ] Enable HTTPS and set `SESSION_COOKIE_SECURE=True` in app config
- [ ] Restrict `/admin/*` to trusted IP ranges via your reverse proxy (nginx/Caddy)
- [ ] Rotate the `ADMIN_SALT` to something unique to your deployment

---

## 🗄️ MongoDB Collections Used

| Collection | Used by Admin |
|---|---|
| `analyses` | Scan history, domain reputation, analytics |
| `reports` | User reports monitoring |
| `admin_logs` | Admin activity logs (auto-created) |

The `admin_logs` collection is created automatically the first time an admin logs in.

---

## 🐛 Troubleshooting

**Login returns 401 every time**
→ Make sure `ADMIN_PASSWORD_HASH` matches your password + salt combination. Re-run the hash generation script.

**"Database not available" errors**
→ Check that `MONGO_URI` is set and the MongoDB cluster is reachable.

**Session expires immediately**
→ `FLASK_SECRET_KEY` must be a stable value. If it changes on restart, all sessions are invalidated. Set it in `.env`.

**Admin panel shows empty data**
→ Normal if no URLs have been scanned yet. Scan a few URLs from the main interface first.
