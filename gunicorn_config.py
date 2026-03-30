# Gunicorn configuration file
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:$PORT"
backlog = 2048

# TLS / HTTPS configuration
# Set CERT_FILE and KEY_FILE environment variables to enable TLS
_cert = os.getenv('TLS_CERT_FILE')
_key  = os.getenv('TLS_KEY_FILE')
if _cert and _key:
    certfile = _cert
    keyfile  = _key
    ssl_version = 'TLSv1_2'          # minimum TLS 1.2
    do_handshake_on_connect = True
    ciphers = (
        'ECDHE-ECDSA-AES256-GCM-SHA384:'
        'ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES128-GCM-SHA256'
    )

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'phishguard'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Performance
preload_app = True
max_requests = 1000
max_requests_jitter = 50

