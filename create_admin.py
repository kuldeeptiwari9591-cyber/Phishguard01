"""
PhishGuard - Admin Setup Script
Run this ONCE to create your admin credentials.
Saves to admin_config.json (never committed to git).

Usage:
    python create_admin.py
"""

import json
import os
import secrets
import getpass

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_config.json')


def create_admin():
    print()
    print("=" * 50)
    print("   PhishGuard Admin Setup")
    print("=" * 50)
    print()

    if os.path.exists(CONFIG_FILE):
        print("Warning: Admin config already exists.")
        overwrite = input("Overwrite it? (yes/no): ").strip().lower()
        if overwrite != 'yes':
            print("Cancelled.")
            try:
                with open(CONFIG_FILE) as f:
                    cfg = json.load(f)
                print(f"Current username: {cfg.get('admin_username', '?')}")
            except:
                pass
            return

    while True:
        username = input("Enter admin username: ").strip()
        if len(username) >= 3:
            break
        print("Username must be at least 3 characters.")

    while True:
        password = getpass.getpass("Enter admin password: ")
        if len(password) < 6:
            print("Password must be at least 6 characters.")
            continue
        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        break

    secret_key = secrets.token_hex(32)

    config = {
        "admin_username": username,
        "admin_password": password,
        "flask_secret_key": secret_key
    }

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

    print()
    print("=" * 50)
    print("Credentials saved to admin_config.json!")
    print(f"Username : {username}")
    print(f"Password : {'*' * len(password)}")
    print("=" * 50)
    print()
    print("Start server:  python app.py")
    print("Login at:      http://localhost:5000/admin/login")
    print()
    print("--- For Render: add these env variables ---")
    print(f"FLASK_SECRET_KEY  =  {secret_key}")
    print(f"ADMIN_USERNAME    =  {username}")
    print(f"ADMIN_PASSWORD    =  {password}")
    print("-------------------------------------------")
    print()
    print("NOTE: admin_config.json is in .gitignore")
    print("It will NOT be uploaded to GitHub.")
    print()


if __name__ == '__main__':
    create_admin()
