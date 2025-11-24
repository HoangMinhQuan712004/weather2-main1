# Demo: Nginx + ModSecurity (WAF) blocking SQL Injection and XSS

This demo runs a vulnerable Flask app behind Nginx with ModSecurity and a tiny set of demo rules that block simple SQL Injection and reflected XSS attempts.

Files added:
- `docker-compose.yml` - orchestration for web and nginx
- `web/` - vulnerable Flask app, Dockerfile, requirements
- `nginx/` - Dockerfile to build Nginx + ModSecurity, configs and demo rules

Quick start (Windows, requires Docker Desktop):

1. Open a terminal in the project folder (`e:/project2/project_quanhieu`).
2. Build and start the services:

```cmd
docker-compose up --build
```

3. Access the app through the WAF proxy: http://localhost:8080

Tests (from another terminal):

- XSS attempt (should be blocked):

```cmd
curl "http://localhost:8080/search?q=<script>alert(1)</script>" -i
```

- SQL Injection attempt (should be blocked):

```cmd
curl "http://localhost:8080/search?q=' OR '1'='1" -i
```

Notes and caveats:
- This project compiles libmodsecurity and Nginx inside the `nginx` image. The build can take several minutes.
- The provided rules are intentionally minimal for demonstration. For a production-grade WAF, use the full OWASP CRS (https://coreruleset.org/) and tune rules carefully.
- Logs: ModSecurity audit log will be written to `/var/log/modsec_audit.log` inside the Nginx container.

If you want, I can:
- Replace the minimal rules with the full OWASP CRS and include instructions to tune it.
- Add helper scripts to run the curl tests and show parsed ModSecurity audit logs.
