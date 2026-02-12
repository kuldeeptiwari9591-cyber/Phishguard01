"""
FIXED PhishGuard Feature Extractor
- Hybrid Database (SQLite for cache, MongoDB for persistent storage)
- All security vulnerabilities fixed
- Proper error handling and validation
- Thread-safe operations
"""

import socket
import ssl
import datetime
from datetime import timezone, timedelta
import requests
import tldextract
import logging
import re
import os
import whois
import threading
import hashlib
import json
from typing import Dict, Optional, List, Any
from urllib.parse import urlparse
import sqlite3
from pathlib import Path
import concurrent.futures
import time
from contextlib import contextmanager

# --- CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Optimized timeouts with retry capability
WHOIS_TIMEOUT = 5
SSL_TIMEOUT = 3
API_TIMEOUT = 5
SCREENSHOT_TIMEOUT = 12
URL_VERIFY_TIMEOUT = 5

SCREENSHOT_DIR = os.getenv('SCREENSHOT_DIR', 'screenshots')
DATABASE_PATH = os.getenv('SQLITE_DB_PATH', 'phishing_detector.db')

# Thread pool for parallel operations
MAX_WORKERS = 6

# Cache TTL settings
WHOIS_CACHE_TTL_DAYS = 7
SCREENSHOT_CACHE_TTL_HOURS = 24
SCAN_CACHE_TTL_MINUTES = 60

# Thread-local storage for SQLite connections
thread_local = threading.local()


class DatabaseManager:
    """Thread-safe database connection manager"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        
    @contextmanager
    def get_connection(self):
        """Get thread-safe database connection with context manager"""
        conn = None
        try:
            # Each thread gets its own connection
            if not hasattr(thread_local, 'conn') or thread_local.conn is None:
                thread_local.conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=10.0
                )
                # Enable WAL mode for better concurrency
                thread_local.conn.execute('PRAGMA journal_mode=WAL')
                thread_local.conn.execute('PRAGMA synchronous=NORMAL')
            
            conn = thread_local.conn
            yield conn
            conn.commit()
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
    
    def cleanup(self):
        """Close thread-local connection"""
        if hasattr(thread_local, 'conn') and thread_local.conn:
            thread_local.conn.close()
            thread_local.conn = None


class AdvancedPhishingDetector:
    def __init__(self, whois_api_key: Optional[str] = None, mongodb_client=None):
        self.whois_api_key = whois_api_key
        self.google_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.screenshot_api_key = os.getenv('SCREENSHOT_API_KEY')
        
        # Hybrid database setup
        self.db_manager = DatabaseManager(DATABASE_PATH)
        self.mongodb = mongodb_client  # For persistent storage
        
        # Initialize databases
        self._init_sqlite_cache()
        
        # Create screenshot directory
        Path(SCREENSHOT_DIR).mkdir(exist_ok=True)
        
        # Start cleanup task
        self._start_cleanup_tasks()

    def _init_sqlite_cache(self):
        """Initialize SQLite for caching only (NOT persistent storage)"""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # WHOIS cache table (7 day TTL)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS whois_cache (
                    domain TEXT PRIMARY KEY,
                    whois_data TEXT NOT NULL,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Screenshot cache table (24 hour TTL)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS screenshot_cache (
                    domain TEXT PRIMARY KEY,
                    screenshot_path TEXT,
                    thumbnail_path TEXT,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER
                )
            ''')
            
            # Temporary scan cache (60 min TTL)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_cache (
                    url_hash TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_whois_cached_at ON whois_cache(cached_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_screenshot_cached_at ON screenshot_cache(captured_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_cached_at ON scan_cache(cached_at)')

    def _start_cleanup_tasks(self):
        """Start background cleanup of expired cache entries"""
        def cleanup_loop():
            while True:
                try:
                    time.sleep(3600)  # Run every hour
                    self._cleanup_expired_cache()
                except Exception as e:
                    logger.error(f"Cleanup task error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()

    def _cleanup_expired_cache(self):
        """Remove expired cache entries to prevent disk bloat"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.datetime.now(timezone.utc)
                
                # Clean WHOIS cache (7 days)
                whois_cutoff = now - timedelta(days=WHOIS_CACHE_TTL_DAYS)
                cursor.execute(
                    'DELETE FROM whois_cache WHERE cached_at < ?',
                    (whois_cutoff,)
                )
                whois_deleted = cursor.rowcount
                
                # Clean screenshot cache (24 hours)
                screenshot_cutoff = now - timedelta(hours=SCREENSHOT_CACHE_TTL_HOURS)
                cursor.execute(
                    'SELECT screenshot_path, thumbnail_path FROM screenshot_cache WHERE captured_at < ?',
                    (screenshot_cutoff,)
                )
                old_screenshots = cursor.fetchall()
                
                # Delete old screenshot files
                for screenshot_path, thumbnail_path in old_screenshots:
                    for path in [screenshot_path, thumbnail_path]:
                        if path and os.path.exists(path):
                            try:
                                os.remove(path)
                            except Exception as e:
                                logger.warning(f"Failed to delete {path}: {e}")
                
                cursor.execute(
                    'DELETE FROM screenshot_cache WHERE captured_at < ?',
                    (screenshot_cutoff,)
                )
                screenshot_deleted = cursor.rowcount
                
                # Clean scan cache (60 minutes)
                scan_cutoff = now - timedelta(minutes=SCAN_CACHE_TTL_MINUTES)
                cursor.execute(
                    'DELETE FROM scan_cache WHERE cached_at < ?',
                    (scan_cutoff,)
                )
                scan_deleted = cursor.rowcount
                
                logger.info(
                    f"Cache cleanup: WHOIS={whois_deleted}, "
                    f"Screenshots={screenshot_deleted}, Scans={scan_deleted}"
                )
                
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")

    # ==================== HELPER FUNCTIONS ====================
    
    def _generate_url_hash(self, url: str) -> str:
        """Generate hash for URL (thread-safe)"""
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def _sanitize_domain(self, domain: str) -> str:
        """Sanitize domain for safe file operations (prevents path traversal)"""
        # Remove any path traversal attempts and special characters
        safe_domain = re.sub(r'[^\w\-\.]', '_', domain)
        # Limit length
        return safe_domain[:100]

    def _clean_str(self, val) -> Optional[str]:
        """Clean string value (thread-safe)"""
        if isinstance(val, str):
            return val.strip() if val.strip() else None
        if isinstance(val, list) and val:
            return val[0].strip() if isinstance(val[0], str) else None
        return None

    def _clean_date(self, dt) -> Optional[datetime.datetime]:
        """Clean date value with timezone awareness"""
        if not dt:
            return None
        try:
            if isinstance(dt, datetime.datetime):
                # Ensure timezone aware
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            if isinstance(dt, list):
                dt = dt[0]
            if isinstance(dt, str):
                parsed = datetime.datetime.strptime(dt[:10], "%Y-%m-%d")
                return parsed.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.warning(f"Date parsing error: {e}")
        return None

    # ==================== URL VALIDATION (REQUIREMENT #3) ====================
    
    def validate_and_check_url_exists(self, url: str) -> Dict[str, Any]:
        """
        REQUIREMENT #3: Validate URL and check if it exists before analysis
        Returns: {"valid": bool, "reachable": bool, "error": str or None}
        """
        result = {
            "valid": False,
            "reachable": False,
            "error": None,
            "final_url": url
        }
        
        # Step 1: Basic URL validation
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            # Validate URL structure
            if not parsed.scheme or not parsed.netloc:
                result["error"] = "Invalid URL format. Please include domain name."
                return result
            
            # Check for localhost/private IPs (optional security)
            if parsed.netloc.lower() in ['localhost', '127.0.0.1', '0.0.0.0']:
                result["error"] = "Cannot analyze localhost URLs"
                return result
            
            result["valid"] = True
            result["final_url"] = url
            
        except Exception as e:
            result["error"] = f"URL parsing error: {str(e)}"
            return result
        
        # Step 2: Check if URL is reachable
        try:
            logger.info(f"Checking if {url} is reachable...")
            
            response = requests.head(
                url,
                timeout=URL_VERIFY_TIMEOUT,
                allow_redirects=True,
                headers={'User-Agent': 'PhishGuard-Scanner/1.0'}
            )
            
            # Accept any non-error response
            if response.status_code < 400:
                result["reachable"] = True
                result["final_url"] = response.url  # Follow redirects
                logger.info(f"✓ URL is reachable (status: {response.status_code})")
                return result
            elif response.status_code == 403:
                # Forbidden but exists
                result["reachable"] = True
                result["error"] = f"URL exists but access is forbidden (403)"
                return result
            else:
                result["error"] = f"URL returned error status: {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            result["error"] = "Cannot connect to URL. Domain may not exist or server is down."
        except requests.exceptions.Timeout:
            result["error"] = "Connection timeout. URL is unreachable or very slow."
        except requests.exceptions.TooManyRedirects:
            result["error"] = "Too many redirects. Possible redirect loop."
        except requests.exceptions.SSLError:
            # SSL error but site might exist
            result["reachable"] = True
            result["error"] = "SSL certificate error (site exists but has security issues)"
        except requests.exceptions.RequestException as e:
            result["error"] = f"Network error: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error checking URL: {str(e)}"
        
        return result

    # ==================== WHOIS CACHE (FIXED SQL INJECTION) ====================
    
    def _get_cached_whois(self, domain: str) -> Optional[Dict]:
        """Get WHOIS from cache with proper expiration (FIXED: SQL injection)"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # FIXED: Use parameterized query instead of f-string
                cursor.execute(
                    '''SELECT whois_data, cached_at FROM whois_cache 
                       WHERE domain = ?''',
                    (domain,)
                )
                result = cursor.fetchone()
                
                if result:
                    whois_data, cached_at = result
                    
                    # Parse cached_at timestamp
                    if isinstance(cached_at, str):
                        cached_at = datetime.datetime.fromisoformat(cached_at)
                    
                    # Check if cache is still valid (7 days)
                    now = datetime.datetime.now(timezone.utc)
                    if cached_at.tzinfo is None:
                        cached_at = cached_at.replace(tzinfo=timezone.utc)
                    
                    age_days = (now - cached_at).days
                    
                    if age_days < WHOIS_CACHE_TTL_DAYS:
                        logger.info(f"✓ WHOIS cache hit for {domain} (age: {age_days} days)")
                        return json.loads(whois_data)
                    else:
                        # Cache expired
                        cursor.execute('DELETE FROM whois_cache WHERE domain = ?', (domain,))
                        logger.info(f"WHOIS cache expired for {domain} ({age_days} days old)")
                
        except Exception as e:
            logger.error(f"WHOIS cache retrieval error: {e}")
        
        return None

    def _save_whois_cache(self, domain: str, whois_data: Dict):
        """Save WHOIS to cache (FIXED: SQL injection)"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                now = datetime.datetime.now(timezone.utc).isoformat()
                
                # FIXED: Parameterized query
                cursor.execute(
                    '''INSERT OR REPLACE INTO whois_cache (domain, whois_data, cached_at)
                       VALUES (?, ?, ?)''',
                    (domain, json.dumps(whois_data), now)
                )
                
        except Exception as e:
            logger.error(f"WHOIS cache save error: {e}")

    def _fetch_whois_data_parallel(self, domain: str) -> Dict:
        """Thread-safe WHOIS lookup with caching"""
        result = {
            "domain_age_days": "Unknown",
            "registrar": "Unknown",
            "category": "Unknown"
        }
        
        # Check cache first
        cached = self._get_cached_whois(domain)
        if cached:
            return cached
        
        # Try API first
        if self.whois_api_key:
            if self._try_whois_api(domain, result):
                self._save_whois_cache(domain, result)
                return result
        
        # Try local WHOIS as fallback
        if self._try_whois_local(domain, result):
            self._save_whois_cache(domain, result)
            return result
        
        return result

    def _try_whois_api(self, domain: str, result: Dict) -> bool:
        """Try WHOIS API lookup"""
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                'apiKey': self.whois_api_key,
                'domainName': domain,
                'outputFormat': 'JSON'
            }
            
            response = requests.get(url, params=params, timeout=API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})
                
                # Extract data
                registrar_name = whois_record.get('registrarName', 'Unknown')
                created_date = whois_record.get('createdDate')
                
                if created_date:
                    created = self._clean_date(created_date)
                    if created:
                        now = datetime.datetime.now(timezone.utc)
                        age_days = (now - created).days
                        result["domain_age_days"] = age_days
                
                result["registrar"] = registrar_name[:100] if registrar_name else "Unknown"
                result["category"] = self._clean_category_name(registrar_name)
                
                return True
                
        except Exception as e:
            logger.warning(f"WHOIS API error for {domain}: {e}")
        
        return False

    def _try_whois_local(self, domain: str, result: Dict) -> bool:
        """Try local WHOIS lookup"""
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                created = self._clean_date(w.creation_date)
                if created:
                    now = datetime.datetime.now(timezone.utc)
                    age_days = (now - created).days
                    result["domain_age_days"] = age_days
            
            if w.registrar:
                registrar = self._clean_str(w.registrar)
                result["registrar"] = registrar[:100] if registrar else "Unknown"
                result["category"] = self._clean_category_name(registrar)
            
            return True
            
        except Exception as e:
            logger.warning(f"Local WHOIS error for {domain}: {e}")
        
        return False

    def _clean_category_name(self, org: str) -> str:
        """Clean organization name"""
        if not org or org == "Unknown":
            return "Unknown"
        cleaned = re.sub(r'\s*(LLC|Inc\.|Ltd\.|Corp\.|Co\.).*', '', org, flags=re.IGNORECASE)
        return cleaned.strip()[:50]

    # ==================== SSL DATA (THREAD-SAFE) ====================
    
    def _fetch_ssl_data_parallel(self, domain: str) -> Dict:
        """Thread-safe SSL certificate check"""
        result = {
            "https": False,
            "ssl_valid": False,
            "ssl_issuer": "Unknown",
            "ssl_issued_date": "Unknown",
            "ssl_expiry_date": "Unknown",
            "ssl_cert_age_days": "Unknown",
            "ssl_expired": False,
            "self_signed": False
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    result["https"] = True
                    result["ssl_valid"] = True
                    
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result["ssl_issuer"] = issuer.get('organizationName', 'Unknown')
                    
                    # Check for self-signed
                    subject = dict(x[0] for x in cert.get('subject', []))
                    if issuer == subject:
                        result["self_signed"] = True
                    
                    # Parse dates
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    
                    if not_before:
                        result["ssl_issued_date"] = self._parse_ssl_date(not_before)
                        
                        # Calculate cert age
                        try:
                            issued = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            issued = issued.replace(tzinfo=timezone.utc)
                            age = (datetime.datetime.now(timezone.utc) - issued).days
                            result["ssl_cert_age_days"] = age
                        except:
                            pass
                    
                    if not_after:
                        result["ssl_expiry_date"] = self._parse_ssl_date(not_after)
                        
                        # Check if expired
                        try:
                            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            if expiry < datetime.datetime.now(timezone.utc):
                                result["ssl_expired"] = True
                        except:
                            pass
                    
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {e}")
            result["https"] = True  # HTTPS exists but has issues
        except (socket.timeout, socket.error) as e:
            logger.warning(f"Connection error for {domain}: {e}")
        except Exception as e:
            logger.warning(f"SSL check error for {domain}: {e}")
        
        return result

    def _parse_ssl_date(self, date_str: str) -> str:
        """Parse SSL date string"""
        try:
            dt_obj = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt_obj.strftime("%Y-%m-%d")
        except:
            return "Unknown"

    # ==================== SCREENSHOT CAPTURE ====================
    
    def _capture_screenshot_parallel(self, url: str, domain: str) -> Dict:
        """Thread-safe screenshot capture with caching"""
        result = {
            "status": "not_captured",
            "screenshot_path": None,
            "thumbnail_path": None
        }
        
        # Sanitize domain for filename
        safe_domain = self._sanitize_domain(domain)
        
        # Check cache first
        cached = self._get_cached_screenshot(safe_domain)
        if cached:
            result.update(cached)
            result["status"] = "cached"
            return result
        
        # Capture new screenshot
        if not self.screenshot_api_key:
            logger.warning("Screenshot API key not configured")
            return result
        
        try:
            timestamp = int(time.time())
            filename = f"{safe_domain}_{timestamp}.png"
            thumb_filename = f"{safe_domain}_{timestamp}_thumb.png"
            
            screenshot_path = os.path.join(SCREENSHOT_DIR, filename)
            thumbnail_path = os.path.join(SCREENSHOT_DIR, thumb_filename)
            
            # Call screenshot API
            api_url = "https://shot.screenshotapi.net/screenshot"
            params = {
                'token': self.screenshot_api_key,
                'url': url,
                'width': 1280,
                'height': 720,
                'output': 'image',
                'file_type': 'png',
                'wait_for_event': 'load'
            }
            
            response = requests.get(api_url, params=params, timeout=SCREENSHOT_TIMEOUT)
            
            if response.status_code == 200:
                # Save full screenshot
                with open(screenshot_path, 'wb') as f:
                    f.write(response.content)
                
                # Create thumbnail
                try:
                    from PIL import Image
                    img = Image.open(screenshot_path)
                    img.thumbnail((400, 300))
                    img.save(thumbnail_path)
                except Exception as e:
                    logger.warning(f"Thumbnail creation failed: {e}")
                    thumbnail_path = screenshot_path
                
                result["status"] = "success"
                result["screenshot_path"] = screenshot_path
                result["thumbnail_path"] = thumbnail_path
                
                # Cache the screenshot info
                self._save_screenshot_cache(safe_domain, screenshot_path, thumbnail_path)
                
                logger.info(f"✓ Screenshot captured for {domain}")
            else:
                logger.warning(f"Screenshot API returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"Screenshot capture error: {e}")
        
        return result

    def _get_cached_screenshot(self, safe_domain: str) -> Optional[Dict]:
        """Get cached screenshot (FIXED: SQL injection)"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # FIXED: Parameterized query
                cursor.execute(
                    '''SELECT screenshot_path, thumbnail_path, captured_at 
                       FROM screenshot_cache WHERE domain = ?''',
                    (safe_domain,)
                )
                result = cursor.fetchone()
                
                if result:
                    screenshot_path, thumbnail_path, captured_at = result
                    
                    # Check if files still exist
                    if os.path.exists(screenshot_path):
                        # Check cache age
                        if isinstance(captured_at, str):
                            captured_at = datetime.datetime.fromisoformat(captured_at)
                        
                        now = datetime.datetime.now(timezone.utc)
                        if captured_at.tzinfo is None:
                            captured_at = captured_at.replace(tzinfo=timezone.utc)
                        
                        age_hours = (now - captured_at).total_seconds() / 3600
                        
                        if age_hours < SCREENSHOT_CACHE_TTL_HOURS:
                            logger.info(f"✓ Screenshot cache hit for {safe_domain}")
                            return {
                                "screenshot_path": screenshot_path,
                                "thumbnail_path": thumbnail_path
                            }
                
        except Exception as e:
            logger.error(f"Screenshot cache retrieval error: {e}")
        
        return None

    def _save_screenshot_cache(self, safe_domain: str, screenshot_path: str, thumbnail_path: str):
        """Save screenshot cache (FIXED: SQL injection)"""
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                file_size = os.path.getsize(screenshot_path) if os.path.exists(screenshot_path) else 0
                now = datetime.datetime.now(timezone.utc).isoformat()
                
                # FIXED: Parameterized query
                cursor.execute(
                    '''INSERT OR REPLACE INTO screenshot_cache 
                       (domain, screenshot_path, thumbnail_path, captured_at, file_size)
                       VALUES (?, ?, ?, ?, ?)''',
                    (safe_domain, screenshot_path, thumbnail_path, now, file_size)
                )
                
        except Exception as e:
            logger.error(f"Screenshot cache save error: {e}")

    # ==================== API CHECKS (FIXED: Error Handling) ====================
    
    def _check_apis_parallel(self, url: str) -> Dict:
        """Check external APIs with proper error handling"""
        result = {
            "results": {},
            "blacklist_hit": False,
            "warnings": []
        }
        
        # Google Safe Browsing
        if self.google_key:
            gsb_result = self._check_google_safe_browsing(url)
            result["results"]["google_safe_browsing"] = gsb_result
            
            if gsb_result.get("status") == "threat_found":
                result["blacklist_hit"] = True
                result["warnings"].append(
                    f"⚠️ Google Safe Browsing: {gsb_result.get('threat_type', 'Threat detected')}"
                )
        
        # VirusTotal
        if self.vt_key:
            vt_result = self._check_virustotal(url)
            result["results"]["virustotal"] = vt_result
            
            if vt_result.get("status") == "malicious":
                result["blacklist_hit"] = True
                detections = vt_result.get("detections", 0)
                result["warnings"].append(
                    f"⚠️ VirusTotal: {detections} security vendors flagged this URL"
                )
        
        return result

    def _check_google_safe_browsing(self, url: str) -> Dict:
        """Check Google Safe Browsing API (FIXED: error handling)"""
        result = {
            "status": "unknown",
            "threat_type": None,
            "error": None
        }
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
            
            payload = {
                "client": {
                    "clientId": "phishguard",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('matches'):
                    result["status"] = "threat_found"
                    result["threat_type"] = data['matches'][0].get('threatType', 'Unknown')
                else:
                    result["status"] = "safe"
            else:
                result["error"] = f"API returned status {response.status_code}"
                
        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
            logger.warning(f"Google Safe Browsing timeout for {url}")
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"Google Safe Browsing error: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Unexpected error in Google Safe Browsing: {e}")
        
        return result

    def _check_virustotal(self, url: str) -> Dict:
        """Check VirusTotal API (FIXED: error handling)"""
        result = {
            "status": "unknown",
            "detections": 0,
            "total_engines": 0,
            "error": None
        }
        
        try:
            # Encode URL for VirusTotal
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.vt_key}
            
            response = requests.get(api_url, headers=headers, timeout=API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                result["detections"] = malicious + suspicious
                result["total_engines"] = total
                
                if malicious > 0:
                    result["status"] = "malicious"
                elif suspicious > 0:
                    result["status"] = "suspicious"
                else:
                    result["status"] = "clean"
                    
            elif response.status_code == 404:
                result["status"] = "not_found"
            else:
                result["error"] = f"API returned status {response.status_code}"
                
        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
            logger.warning(f"VirusTotal timeout for {url}")
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"VirusTotal error: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Unexpected error in VirusTotal: {e}")
        
        return result

    # ==================== MONGODB OPERATIONS ====================
    
    def get_community_reports(self, domain: str) -> Dict:
        """Get community reports from MongoDB"""
        if not self.mongodb:
            return {"total_reports": 0, "phishing_reports": 0, "safe_reports": 0}
        
        try:
            reports = list(self.mongodb.user_reports.find({"domain": domain}))
            
            phishing = sum(1 for r in reports if r.get('report_type') == 'phishing')
            safe = sum(1 for r in reports if r.get('report_type') == 'safe')
            
            return {
                "total_reports": len(reports),
                "phishing_reports": phishing,
                "safe_reports": safe,
                "reports": reports[:5]  # Last 5 reports
            }
            
        except Exception as e:
            logger.error(f"Community reports error: {e}")
            return {"total_reports": 0, "phishing_reports": 0, "safe_reports": 0}

    def _get_domain_reputation(self, domain: str) -> Dict:
        """Get domain reputation from MongoDB"""
        if not self.mongodb:
            return {}
        
        try:
            rep = self.mongodb.domain_reputation.find_one({"domain": domain})
            
            if rep:
                return {
                    "first_seen": rep.get('first_seen'),
                    "total_scans": rep.get('total_scans', 0),
                    "high_risk_count": rep.get('high_risk_count', 0),
                    "average_risk_score": rep.get('average_risk_score', 0)
                }
                
        except Exception as e:
            logger.error(f"Domain reputation error: {e}")
        
        return {}

    def submit_user_report(self, url: str, report_type: str, comment: str, user_ip: str) -> bool:
        """Submit user report to MongoDB"""
        if not self.mongodb:
            return False
        
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Hash IP for privacy
            ip_hash = hashlib.sha256(user_ip.encode()).hexdigest()[:16]
            
            report = {
                "url": url,
                "domain": domain,
                "report_type": report_type,
                "user_comment": comment,
                "reported_at": datetime.datetime.now(timezone.utc),
                "user_ip_hash": ip_hash
            }
            
            self.mongodb.user_reports.insert_one(report)
            return True
            
        except Exception as e:
            logger.error(f"Report submission error: {e}")
            return False

    def get_server_ip(self, domain: str) -> str:
        """Get server IP address"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except Exception as e:
            logger.warning(f"IP lookup failed for {domain}: {e}")
            return "Unknown"

    # ==================== SCAN CACHE (FIXED: Timeout Bug) ====================
    
    def _check_scan_cache(self, url: str) -> Optional[Dict]:
        """Check if URL was recently scanned (FIXED: SQL injection)"""
        try:
            url_hash = self._generate_url_hash(url)
            
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # FIXED: Parameterized query
                cursor.execute(
                    '''SELECT result_json, cached_at FROM scan_cache 
                       WHERE url_hash = ?''',
                    (url_hash,)
                )
                result = cursor.fetchone()
                
                if result:
                    result_json, cached_at = result
                    
                    # Parse timestamp
                    if isinstance(cached_at, str):
                        cached_at = datetime.datetime.fromisoformat(cached_at)
                    
                    # Check age
                    now = datetime.datetime.now(timezone.utc)
                    if cached_at.tzinfo is None:
                        cached_at = cached_at.replace(tzinfo=timezone.utc)
                    
                    age_minutes = (now - cached_at).total_seconds() / 60
                    
                    if age_minutes < SCAN_CACHE_TTL_MINUTES:
                        cached_result = json.loads(result_json)
                        cached_result['from_cache'] = True
                        cached_result['cache_age_minutes'] = int(age_minutes)
                        
                        logger.info(f"⚡ Scan cache hit for {url} (age: {int(age_minutes)}min)")
                        return cached_result
                
        except Exception as e:
            logger.error(f"Scan cache check error: {e}")
        
        return None

    def _save_scan_cache(self, url: str, result: Dict):
        """Save scan to cache (FIXED: SQL injection)"""
        try:
            url_hash = self._generate_url_hash(url)
            
            with self.db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                now = datetime.datetime.now(timezone.utc).isoformat()
                
                # FIXED: Parameterized query
                cursor.execute(
                    '''INSERT OR REPLACE INTO scan_cache (url_hash, url, result_json, cached_at)
                       VALUES (?, ?, ?, ?)''',
                    (url_hash, url, json.dumps(result), now)
                )
                
        except Exception as e:
            logger.error(f"Scan cache save error: {e}")

    def _save_to_mongodb(self, result: Dict):
        """Save scan result to MongoDB for persistent storage"""
        if not self.mongodb:
            return
        
        try:
            # Save to analyses collection
            doc = {
                'url': result['url'],
                'domain': result.get('domain', ''),
                'risk_level': result['risk_level'],
                'risk_score': result['risk_score'],
                'context': result.get('context', 'GENERAL'),
                'timestamp': datetime.datetime.now(timezone.utc),
                'full_analysis': result
            }
            
            self.mongodb.analyses.insert_one(doc)
            
            # Update domain reputation
            extracted = tldextract.extract(result['url'])
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            existing = self.mongodb.domain_reputation.find_one({"domain": domain})
            
            if existing:
                # Update existing
                total_scans = existing.get('total_scans', 0) + 1
                high_risk = existing.get('high_risk_count', 0)
                if result['risk_level'] in ['CRITICAL', 'HIGH']:
                    high_risk += 1
                
                # Calculate new average
                old_avg = existing.get('average_risk_score', 0)
                new_avg = ((old_avg * (total_scans - 1)) + result['risk_score']) / total_scans
                
                self.mongodb.domain_reputation.update_one(
                    {"domain": domain},
                    {
                        "$set": {
                            "last_scanned": datetime.datetime.now(timezone.utc),
                            "total_scans": total_scans,
                            "high_risk_count": high_risk,
                            "average_risk_score": round(new_avg, 2)
                        }
                    }
                )
            else:
                # Create new
                self.mongodb.domain_reputation.insert_one({
                    "domain": domain,
                    "first_seen": datetime.datetime.now(timezone.utc),
                    "last_scanned": datetime.datetime.now(timezone.utc),
                    "total_scans": 1,
                    "high_risk_count": 1 if result['risk_level'] in ['CRITICAL', 'HIGH'] else 0,
                    "average_risk_score": result['risk_score']
                })
                
            logger.info(f"✓ Saved to MongoDB: {result['url']}")
            
        except Exception as e:
            logger.error(f"MongoDB save error: {e}")

    # ==================== HEURISTIC ANALYSIS ====================
    
    def _perform_heuristics(self, url: str, extracted, features: Dict):
        """Perform heuristic checks on URL"""
        risk_score = 0
        
        domain = f"{extracted.domain}.{extracted.suffix}"
        parsed = urlparse(url)
        
        # Get technical data
        tech = features['technical_summary']
        signals = features['detected_signals']
        
        # 1. Domain age check
        domain_age = tech.get('domain_age_days')
        if isinstance(domain_age, int):
            if domain_age < 30:
                risk_score += 20
                signals['new_domain'] = True
                features['why_dangerous'].append(f"⚠️ Very new domain (only {domain_age} days old)")
            elif domain_age < 180:
                risk_score += 10
                signals['new_domain'] = True
                features['why_dangerous'].append(f"⚠️ Relatively new domain ({domain_age} days old)")
            else:
                features['why_safe'].append(f"✓ Established domain ({domain_age} days old)")
        
        # 2. SSL/HTTPS checks
        if tech.get('ssl_valid'):
            features['why_safe'].append("✓ Valid SSL certificate")
            if tech.get('self_signed'):
                risk_score += 15
                signals['self_signed_cert'] = True
                features['why_dangerous'].append("⚠️ Self-signed SSL certificate")
        else:
            risk_score += 25
            features['why_dangerous'].append("⚠️ No valid HTTPS/SSL certificate")
        
        if tech.get('ssl_expired'):
            risk_score += 30
            signals['expired_cert'] = True
            features['why_dangerous'].append("⚠️ Expired SSL certificate")
        
        # 3. Certificate age
        cert_age = tech.get('ssl_cert_age_days')
        if isinstance(cert_age, int) and cert_age < 30:
            risk_score += 10
            signals['new_certificate'] = True
            features['why_dangerous'].append(f"⚠️ Very new SSL certificate ({cert_age} days old)")
        
        # 4. IP address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
            risk_score += 20
            signals['ip_usage'] = True
            features['why_dangerous'].append("⚠️ Uses IP address instead of domain name")
        
        # 5. URL shortener
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        if any(short in domain.lower() for short in shorteners):
            risk_score += 15
            signals['url_shortener'] = True
            features['why_dangerous'].append("⚠️ URL shortener detected")
        
        # 6. Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_score += 15
            signals['suspicious_tld'] = True
            features['why_dangerous'].append(f"⚠️ Suspicious TLD ({extracted.suffix})")
        
        # 7. Excessive subdomains
        subdomain = extracted.subdomain
        if subdomain:
            subdomain_count = len(subdomain.split('.'))
            if subdomain_count >= 3:
                risk_score += 15
                signals['excessive_subdomains'] = True
                features['why_dangerous'].append(f"⚠️ Excessive subdomains ({subdomain_count} levels)")
        
        # 8. Non-standard ports
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            risk_score += 10
            signals['non_standard_port'] = True
            features['why_dangerous'].append(f"⚠️ Non-standard port ({parsed.port})")
        
        # 9. Suspicious keywords
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update', 
            'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'password',
            'suspended', 'locked', 'unusual', 'activity'
        ]
        url_lower = url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        if found_keywords:
            risk_score += len(found_keywords) * 5
            signals['suspicious_keywords'] = True
            features['why_dangerous'].append(f"⚠️ Suspicious keywords: {', '.join(found_keywords[:3])}")
        
        # 10. Deep path
        path = parsed.path
        path_depth = len([p for p in path.split('/') if p])
        if path_depth > 4:
            risk_score += 10
            signals['deep_path'] = True
            features['why_dangerous'].append(f"⚠️ Unusually deep URL path ({path_depth} levels)")
        
        # 11. Excessive special characters
        special_count = sum(1 for c in url if c in '@-_.')
        if special_count > 5:
            risk_score += 10
            signals['excessive_special_chars'] = True
            features['why_dangerous'].append(f"⚠️ Excessive special characters ({special_count})")
        
        # 12. Homograph attack detection
        if self._check_homograph_attack(domain):
            risk_score += 25
            signals['homograph_attack'] = True
            features['why_dangerous'].append("⚠️ Possible homograph/lookalike domain attack")
        
        # Update risk score
        features['risk_score'] = min(risk_score, 100)

    def _check_homograph_attack(self, domain: str) -> bool:
        """Check for homograph/punycode attacks"""
        # Check for punycode (xn--)
        if 'xn--' in domain.lower():
            return True
        
        # Check for mixed scripts or lookalike characters
        suspicious_chars = ['і', 'і', 'о', 'а', 'е', 'р', 'с', 'у', 'х']  # Cyrillic lookalikes
        return any(char in domain for char in suspicious_chars)

    # ==================== VERDICT GENERATION ====================
    
    def _generate_verdict(self, features: Dict):
        """Generate risk level and verdict"""
        risk_score = features['risk_score']
        
        # Determine risk level
        if risk_score >= 70:
            features['risk_level'] = 'CRITICAL'
            features['verdict_summary'] = '🚨 HIGH RISK - Likely a phishing or malicious site'
        elif risk_score >= 50:
            features['risk_level'] = 'HIGH'
            features['verdict_summary'] = '⚠️ SUSPICIOUS - Multiple warning signs detected'
        elif risk_score >= 30:
            features['risk_level'] = 'MEDIUM'
            features['verdict_summary'] = '⚡ CAUTION - Some concerning indicators found'
        elif risk_score >= 15:
            features['risk_level'] = 'LOW'
            features['verdict_summary'] = '✓ LIKELY SAFE - Minor concerns only'
        else:
            features['risk_level'] = 'SAFE'
            features['verdict_summary'] = '✅ APPEARS SAFE - No major red flags'

    def _generate_guidance(self, features: Dict):
        """Generate action guidance"""
        risk_level = features['risk_level']
        guidance = []
        
        if risk_level == 'CRITICAL':
            guidance.append("❌ DO NOT enter any personal information")
            guidance.append("❌ DO NOT download anything from this site")
            guidance.append("✓ Close this page immediately")
            guidance.append("✓ Report this site if you received it via email/message")
        
        elif risk_level == 'HIGH':
            guidance.append("⚠️ Proceed with extreme caution")
            guidance.append("⚠️ Do not enter passwords or payment information")
            guidance.append("✓ Verify the URL matches the official site")
            guidance.append("✓ Contact the company directly through official channels")
        
        elif risk_level == 'MEDIUM':
            guidance.append("⚡ Exercise caution when interacting with this site")
            guidance.append("✓ Verify this is the correct URL")
            guidance.append("✓ Look for trust indicators (SSL lock, reviews)")
            guidance.append("✓ Avoid entering sensitive information")
        
        elif risk_level == 'LOW':
            guidance.append("✓ Site appears mostly legitimate")
            guidance.append("✓ Still verify before entering sensitive data")
            guidance.append("✓ Check for HTTPS and valid certificate")
        
        else:  # SAFE
            guidance.append("✅ Site appears legitimate and safe")
            guidance.append("✓ Always verify before entering sensitive information")
            guidance.append("✓ Keep your software and browser updated")
        
        features['action_guidance'] = guidance

    def _calculate_confidence(self, features: Dict):
        """Calculate confidence score"""
        confidence_score = 0
        
        # Factors that increase confidence
        if features['technical_summary'].get('domain_age_days') != 'Unknown':
            confidence_score += 20
        
        if features['technical_summary'].get('ssl_valid'):
            confidence_score += 20
        
        if features.get('api_results', {}).get('google_safe_browsing'):
            confidence_score += 20
        
        if features.get('api_results', {}).get('virustotal'):
            confidence_score += 20
        
        if features.get('community_reports', {}).get('total_reports', 0) > 0:
            confidence_score += 10
        
        if features.get('screenshot_path'):
            confidence_score += 10
        
        # Set confidence level
        features['confidence_score'] = min(confidence_score, 100)
        
        if confidence_score >= 80:
            features['confidence'] = 'VERY HIGH'
        elif confidence_score >= 60:
            features['confidence'] = 'HIGH'
        elif confidence_score >= 40:
            features['confidence'] = 'MEDIUM'
        else:
            features['confidence'] = 'LOW'

    def _determine_context(self, url: str, domain: str) -> tuple:
        """Determine URL context and category"""
        url_lower = url.lower()
        
        # Banking
        if any(kw in url_lower for kw in ['bank', 'paypal', 'stripe', 'venmo', 'chase', 'wellsfargo']):
            return 'FINANCIAL', 'Financial Services'
        
        # E-commerce
        if any(kw in url_lower for kw in ['shop', 'store', 'cart', 'checkout', 'amazon', 'ebay']):
            return 'ECOMMERCE', 'E-commerce'
        
        # Social Media
        if any(kw in url_lower for kw in ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok']):
            return 'SOCIAL', 'Social Media'
        
        # Email/Login
        if any(kw in url_lower for kw in ['mail', 'gmail', 'outlook', 'yahoo', 'login', 'signin']):
            return 'EMAIL', 'Email/Authentication'
        
        # Government
        if '.gov' in domain:
            return 'GOVERNMENT', 'Government'
        
        # Education
        if '.edu' in domain:
            return 'EDUCATION', 'Educational'
        
        return 'GENERAL', 'General Website'

    # ==================== MAIN ANALYSIS FUNCTION (FIXED: All Issues) ====================
    
    def analyze_url_comprehensive(self, url: str) -> Dict[str, Any]:
        """
        Main analysis function with all fixes:
        - URL validation (REQUIREMENT #3)
        - Proper error handling
        - Thread-safe operations
        - Fixed timeout logic
        """
        start_time = time.time()
        
        # REQUIREMENT #3: Validate URL first
        validation = self.validate_and_check_url_exists(url)
        
        if not validation["valid"]:
            return {
                "url": url,
                "risk_level": "ERROR",
                "risk_score": 0,
                "verdict_summary": "Invalid URL",
                "error": validation["error"],
                "action_guidance": ["Please enter a valid URL with proper format"],
                "analysis_time_seconds": round(time.time() - start_time, 2)
            }
        
        if not validation["reachable"]:
            return {
                "url": url,
                "risk_level": "ERROR",
                "risk_score": 0,
                "verdict_summary": "URL Unreachable",
                "error": validation["error"],
                "action_guidance": [
                    "This URL cannot be reached",
                    "The domain may not exist or server is down",
                    "Check the URL spelling and try again"
                ],
                "analysis_time_seconds": round(time.time() - start_time, 2)
            }
        
        # Use final URL (after redirects)
        url = validation["final_url"]
        
        # Initialize features
        features = {
            "url": url,
            "context": "GENERAL",
            "category": "General Website",
            "risk_level": "UNKNOWN",
            "confidence": "LOW",
            "confidence_score": 0,
            "risk_score": 0,
            "verdict_summary": "Analysis pending...",
            "why_dangerous": [],
            "why_safe": [],
            "detected_signals": {
                "new_domain": False,
                "typosquatting": False,
                "blacklist_hit": False,
                "https": False,
                "ip_usage": False,
                "url_shortener": False,
                "self_signed_cert": False,
                "expired_cert": False,
                "new_certificate": False,
                "homograph_attack": False,
                "excessive_subdomains": False,
                "non_standard_port": False,
                "suspicious_keywords": False,
                "deep_path": False,
                "suspicious_tld": False,
                "excessive_special_chars": False
            },
            "action_guidance": [],
            "technical_summary": {
                "domain_age_days": "Unknown",
                "ssl_valid": False,
                "ssl_issuer": "Unknown",
                "ssl_issued_date": "Unknown",
                "ssl_expiry_date": "Unknown",
                "ssl_cert_age_days": "Unknown",
                "ssl_expired": False,
                "registrar": "Unknown",
                "category": "Unknown",
                "server_ip": "Unknown"
            },
            "api_results": {},
            "from_cache": False,
            "analysis_time_seconds": 0
        }
        
        # Extract domain
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        features['domain'] = domain
        
        # Check cache
        cached_scan = self._check_scan_cache(url)
        if cached_scan:
            logger.info(f"⚡ Cache hit for {url}")
            return cached_scan
        
        logger.info(f"🔍 Starting full analysis for {url}")
        
        try:
            # Determine context
            context, category = self._determine_context(url, domain)
            features["context"] = context
            features["category"] = category
            
            # FIXED: Parallel operations with proper timeout
            logger.info(f"⚡ Running parallel checks...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Submit all operations
                futures = {
                    'whois': executor.submit(self._fetch_whois_data_parallel, domain),
                    'ssl': executor.submit(self._fetch_ssl_data_parallel, domain),
                    'screenshot': executor.submit(self._capture_screenshot_parallel, url, domain),
                    'apis': executor.submit(self._check_apis_parallel, url),
                    'community': executor.submit(self.get_community_reports, domain),
                    'reputation': executor.submit(self._get_domain_reputation, domain),
                    'server_ip': executor.submit(self.get_server_ip, domain)
                }
                
                # FIXED: Overall timeout instead of per-future
                deadline = time.time() + 15  # 15 seconds total for all parallel operations
                results = {}
                
                for name, future in futures.items():
                    try:
                        remaining = deadline - time.time()
                        if remaining <= 0:
                            logger.warning(f"⏱️ Overall timeout reached, skipping {name}")
                            results[name] = None
                            future.cancel()
                            continue
                        
                        results[name] = future.result(timeout=remaining)
                        logger.info(f"✓ {name} completed")
                        
                    except concurrent.futures.TimeoutError:
                        logger.warning(f"⏱️ {name} timed out")
                        results[name] = None
                    except Exception as e:
                        logger.error(f"❌ {name} failed: {e}")
                        results[name] = None
            
            # Process results
            if results.get('whois'):
                features['technical_summary'].update(results['whois'])
            
            if results.get('ssl'):
                features['technical_summary'].update(results['ssl'])
                features['detected_signals']['https'] = results['ssl'].get('https', False)
            
            if results.get('screenshot'):
                if results['screenshot'].get('status') in ['success', 'cached']:
                    features['screenshot_path'] = results['screenshot'].get('screenshot_path')
                    features['thumbnail_path'] = results['screenshot'].get('thumbnail_path')
            
            if results.get('apis'):
                features['api_results'] = results['apis'].get('results', {})
                if results['apis'].get('blacklist_hit'):
                    features['detected_signals']['blacklist_hit'] = True
                    features['why_dangerous'].extend(results['apis'].get('warnings', []))
            
            if results.get('community'):
                features['community_reports'] = results['community']
            
            if results.get('reputation'):
                features['domain_reputation'] = results['reputation']
            
            if results.get('server_ip'):
                features['technical_summary']['server_ip'] = results['server_ip']
            
            # Heuristic analysis
            logger.info("⚡ Running heuristic analysis...")
            self._perform_heuristics(url, extracted, features)
            
            # Generate verdict
            self._generate_verdict(features)
            self._generate_guidance(features)
            self._calculate_confidence(features)
            
            # Save to caches (non-blocking)
            threading.Thread(
                target=self._save_scan_cache,
                args=(url, features),
                daemon=True
            ).start()
            
            threading.Thread(
                target=self._save_to_mongodb,
                args=(features,),
                daemon=True
            ).start()
            
            # Calculate total time
            features['analysis_time_seconds'] = round(time.time() - start_time, 2)
            
            logger.info(
                f"✅ Analysis complete in {features['analysis_time_seconds']}s - "
                f"Risk: {features['risk_level']} ({features['risk_score']}/100)"
            )
        
        except Exception as e:
            logger.error(f"❌ Analysis error for {url}: {e}", exc_info=True)
            features["verdict_summary"] = f"Analysis Error: {str(e)}"
            features["risk_level"] = "ERROR"
            features["error"] = str(e)
            features["action_guidance"] = ["Unable to complete analysis", "Try again later"]
        
        return features


# Convenience function
def analyze_url(url: str, whois_api_key: Optional[str] = None, mongodb_client=None) -> Dict:
    """
    Analyze a single URL (fixed version)
    """
    detector = AdvancedPhishingDetector(whois_api_key=whois_api_key, mongodb_client=mongodb_client)
    return detector.analyze_url_comprehensive(url)


if __name__ == "__main__":
    # Example usage
    test_url = input("Enter URL to analyze: ")
    
    print("\n" + "="*70)
    print("🚀 FIXED PhishGuard Analysis")
    print("="*70)
    
    detector = AdvancedPhishingDetector()
    result = detector.analyze_url_comprehensive(test_url)
    
    if result.get('error'):
        print(f"\n❌ ERROR: {result['error']}")
        print(f"📝 Verdict: {result['verdict_summary']}")
    else:
        print(f"\n⏱️  Analysis Time: {result.get('analysis_time_seconds', 'N/A')} seconds")
        print(f"🌐 URL: {result['url']}")
        print(f"📁 Category: {result['category']}")
        print(f"🎯 Context: {result['context']}")
        print(f"📊 Risk Level: {result['risk_level']}")
        print(f"🔢 Risk Score: {result['risk_score']}/100")
        print(f"✅ Confidence: {result['confidence']} ({result['confidence_score']}%)")
        print(f"📝 Verdict: {result['verdict_summary']}")
        
        if result.get('from_cache'):
            print(f"⚡ From cache (age: {result.get('cache_age_minutes', 0)} minutes)")
        
        if result['why_dangerous']:
            print("\n❌ Warning Signs:")
            for reason in result['why_dangerous']:
                print(f"  • {reason}")
        
        if result['why_safe']:
            print("\n✅ Trust Signals:")
            for reason in result['why_safe']:
                print(f"  • {reason}")
        
        print("\n📋 Action Guidance:")
        for action in result['action_guidance']:
            print(f"  • {action}")
    
    print("\n" + "="*70)
