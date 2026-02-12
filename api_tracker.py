"""
API Usage Tracker
Wraps API calls to track usage and respect enable/disable settings
"""

import json
import os
from datetime import datetime, timezone

ADMIN_USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_users.json')

def is_api_enabled(api_name):
    """Check if an API is enabled."""
    try:
        if os.path.exists(ADMIN_USERS_FILE):
            with open(ADMIN_USERS_FILE, 'r') as f:
                users = json.load(f)
            api_settings = users.get('api_settings', {})
            return api_settings.get(api_name, {}).get('enabled', True)
    except:
        pass
    return True  # Default to enabled if file doesn't exist


def track_api_usage(api_name):
    """Increment usage counter for an API."""
    try:
        if not os.path.exists(ADMIN_USERS_FILE):
            return
        
        with open(ADMIN_USERS_FILE, 'r') as f:
            users = json.load(f)
        
        api_settings = users.get('api_settings', {})
        if api_name in api_settings:
            api_settings[api_name]['usage_count'] = api_settings[api_name].get('usage_count', 0) + 1
            api_settings[api_name]['last_used'] = datetime.now(timezone.utc).isoformat()
            users['api_settings'] = api_settings
            
            with open(ADMIN_USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
    except Exception as e:
        # Don't break if tracking fails
        pass
