# PhishGuard Admin Panel — Quick Start Guide

## ✅ Complete Setup in 3 Steps

### Step 1: Create Admin Credentials (LOCAL ONLY — run once)

```bash
python create_admin.py
```

You'll be asked:
```
Enter admin username: yourname
Enter admin password: (hidden input)
Confirm admin password: (hidden input)
```

This creates `admin_config.json` — **never commit this file** (it's in `.gitignore`).

The script will print your Render environment variables at the end:
```
FLASK_SECRET_KEY  =  abc123...
ADMIN_USERNAME    =  yourname  
ADMIN_PASSWORD    =  yourpassword
```

---

### Step 2: Run Locally

```bash
python app.py
```

Go to: **http://localhost:5000/admin/login**

Login with the username/password you just created.

---

### Step 3: Deploy to Render

**A. Push to GitHub:**
```bash
git add .
git commit -m "Add admin panel"
git push
```

**B. In Render Dashboard → Environment Variables, add exactly 3:**

| Key | Value |
|---|---|
| `FLASK_SECRET_KEY` | The long hex string from Step 1 |
| `ADMIN_USERNAME` | Your chosen username |
| `ADMIN_PASSWORD` | Your chosen password (plain text, not hashed) |
| `MONGO_URI` | Your MongoDB connection string |

**C. Deploy**

Once deployed, go to: `https://yourapp.onrender.com/admin/login`

---

## 🔧 Troubleshooting

### "Invalid credentials" even with correct password
- Make sure `ADMIN_PASSWORD` in Render is **plain text**, not a hash
- Username and password are **case-sensitive**
- Re-run `python create_admin.py` locally to verify your credentials

### 404 "Not found" on /admin routes
- Verify you committed and pushed the **latest** `app.py` and `admin_routes.py`
- Check Render logs for import errors
- Make sure all files from the zip are in your repo

### "Database not available" in admin panel
- Add `MONGO_URI` to Render environment variables
- In MongoDB Atlas → Network Access → allow `0.0.0.0/0`

---

## 📂 Files You Must Commit

✅ Commit these:
- `app.py`
- `admin_routes.py`
- `admin_panel.html`
- `admin_login.html`
- `create_admin.py`
- `render.yaml`
- `.gitignore`

❌ NEVER commit:
- `admin_config.json` ← contains your password in plain text
- `apikey.env` ← already in .gitignore

---

## 🎯 Admin Panel Features

All 10 features are live:

| Feature | URL |
|---|---|
| **Login** | `/admin/login` |
| **Dashboard** | `/admin/dashboard` |
| **Scan History** | API: `/admin/api/scans` |
| **Domain Reputation** | API: `/admin/api/domains` |
| **User Reports** | API: `/admin/api/reports` |
| **Screenshots** | API: `/admin/api/screenshots` |
| **System Health** | API: `/admin/api/health` |
| **Analytics** | API: `/admin/api/analytics` |
| **Activity Logs** | API: `/admin/api/logs` |
| **CSV Export** | API: `/admin/api/export/scans` |

The dashboard is a **single-page app** — all panels are accessible from the sidebar after login.

---

## 🔒 Security Notes

- Passwords are stored in **plain text** in `admin_config.json` for simplicity
- This file is in `.gitignore` so it stays local only
- For Render, you add the password as an environment variable
- Sessions expire after 8 hours of inactivity
- All admin routes require authentication (session-based)

---

## 💡 How `create_admin.py` Works

**If you answer "no" to overwrite:**
```
Warning: Admin config already exists.
Overwrite it? (yes/no): no
Cancelled.
Current username: yourname
```
↑ This is **correct behavior** — it shows your current username and exits.

**To create new credentials, answer "yes":**
```
Overwrite it? (yes/no): yes
Enter admin username: newname
Enter admin password: 
```

---

## 📞 Support

If you see errors:
1. Check the Render logs for the exact error message
2. Verify all environment variables are set correctly
3. Make sure MongoDB Atlas allows connections from `0.0.0.0/0`
4. Confirm you pushed the latest code to GitHub
