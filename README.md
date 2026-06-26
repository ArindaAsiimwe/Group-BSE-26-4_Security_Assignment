# 8TechBank — Security Assessment Project

## Overview

A deliberately vulnerable banking web application built in Python (Flask) for the BSE 4202 Software Security practical assignment. The repository contains:

- `/src/vulnerable/` — Intentionally insecure version (6 embedded vulnerability patterns)
- `/src/secure/` — Defense-in-depth fixed version (all 6 vulnerabilities remediated)
- `/exploits/` — Proof-of-concept exploit scripts (Task 2)
- `/screenshots/` — Evidence screenshots
- `/report/` — Security assessment report (PDF)

---

## Requirements

- Python 3.10+
- pip

---

## Setup

### 1. Install dependencies

```bash
# From the project root
pip install -r requirements.txt
```

### 2. Run the **Vulnerable** app (Task 1 & 2 — port 5000)

```bash
cd src/vulnerable
python3 app.py
# App runs at http://127.0.0.1:5000
```

> **Warning:** This is intentionally insecure. Never expose to a network.

### 3. Run the **Secure** app (Task 3 & 4 — port 5001)

```bash
cd src/secure
SECRET_KEY=changeme JWT_SECRET=changeme2 python3 app.py
# App runs at http://127.0.0.1:5001
```

---

## Test Credentials

| Username | Password  | Role  |
| -------- | --------- | ----- |
| admin    | admin123  | admin |
| user1    | user1pass | user  |
| user2    | user2pass | user  |

---

## Running Exploit Scripts (Task 2)

> All exploits must be run **while the vulnerable app is running** on port 5000.

```bash
# Exploit A: SQL Injection
python3 exploits/sqli_exploit.py

# Exploit B: XSS
python3 exploits/xss_exploit.py

# Exploit C: CSRF — open in browser while logged into vulnerable app
# Serve it: python3 -m http.server 8888 (from project root)
# Then open: http://localhost:8888/exploits/csrf_exploit.html

# Exploit D: IDOR
python3 exploits/idor_exploit.py
```

---

## Docker (Task 4.3)

```bash
# Build and run sandboxed production environment
docker compose up --build

# App served via nginx at http://localhost:80
# (requires SECRET_KEY and JWT_SECRET env vars)
```

---

## API Endpoints (Secure App — Task 4)

| Method | Endpoint             | Auth      | Description                      |
| ------ | -------------------- | --------- | -------------------------------- |
| POST   | `/api/auth/token`  | None      | Get JWT (rate-limited: 5/min/IP) |
| GET    | `/api/me`          | JWT       | Get current user info            |
| POST   | `/api/transfer`    | JWT       | Perform fund transfer            |
| GET    | `/api/admin/users` | JWT+Admin | List all users (admin only)      |

### Example: Get a JWT token

```bash
curl -X POST http://127.0.0.1:5001/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "user1pass"}'
```

### Example: Use the token

```bash
curl http://127.0.0.1:5001/api/me \
  -H "Authorization: Bearer <your_token_here>"
```

---

## Vulnerability Summary (Task 1)

| # | Vulnerability         | CWE     | OWASP 2021 | CVSS | File / Line           |
| - | --------------------- | ------- | ---------- | ---- | --------------------- |
| 1 | SQL Injection (Login) | CWE-89  | A03        | 9.8  | vulnerable/app.py:89  |
| 2 | Reflected XSS         | CWE-79  | A03        | 7.4  | vulnerable/app.py:114 |
| 3 | Stored XSS            | CWE-79  | A03        | 8.8  | vulnerable/app.py:160 |
| 4 | IDOR                  | CWE-639 | A01        | 7.5  | vulnerable/app.py:200 |
| 5 | Plaintext Passwords   | CWE-256 | A02        | 8.1  | vulnerable/app.py:229 |
| 6 | Missing CSRF          | CWE-352 | A01        | 8.0  | vulnerable/app.py:119 |

---

## AI Tool Usage Declaration

This project was developed with assistance from an AI coding assistant (Antigravity / Google DeepMind). The AI was used for:

- Scaffolding secure Flask application code (Task 3)
- Generating exploit script templates (Task 2)
- Drafting README structure

All generated code was reviewed, understood, and modified by the group members to ensure correctness and to meet assignment-specific requirements.
