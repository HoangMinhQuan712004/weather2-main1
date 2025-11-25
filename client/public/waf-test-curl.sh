#!/bin/bash
# WAF test curl script
# Adjust TARGET to point to your proxy or application (e.g. http://localhost:8080)
TARGET="http://localhost:3000"

echo "Running WAF test curl script against $TARGET"

# SQL Injection
curl -i "${TARGET}/?id=1'%20OR%20'1'='1"
curl -i "${TARGET}/?id=1'%20OR%201=1--"

# XSS
curl -i "${TARGET}/?search=<script>alert(1)</script>"

# Path traversal
curl -i "${TARGET}/download?file=../../../etc/passwd"

# Command injection
curl -i "${TARGET}/ping?host=127.0.0.1; ls -la"

# LFI
curl -i "${TARGET}/?page=../../../../etc/passwd"

# SSRF
curl -i "${TARGET}/fetch?url=http://169.254.169.254/latest/meta-data/"

# Open redirect
curl -i "${TARGET}/redirect?url=http://evil.com"

# Header injection (example encoded)
curl -i "${TARGET}/page?url=%0d%0aSet-Cookie:%20admin=true"

echo "Done"
