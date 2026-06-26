"""
8TechBank Secure Application — Task 3: Defense in Depth
All six vulnerabilities from the vulnerable version have been fixed.
"""

from flask import Flask, render_template, request, redirect, session, url_for, jsonify, g
import sqlite3
import os
import secrets
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from functools import wraps
import re

# --- JWT & security deps (installed via requirements.txt) ---
import bcrypt
import jwt as pyjwt
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ==================== FIX 6a: SECURE SESSION / SECRET KEY ====================
# Use a cryptographically random secret key (never hardcoded)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ==================== FIX 6b: SECURE SESSION CONFIGURATION ====================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevent JS access to session cookie
    SESSION_COOKIE_SECURE=False,        # Set True in HTTPS production
    SESSION_COOKIE_SAMESITE='Strict',   # Prevent CSRF via cookie
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # 15-min timeout
)

JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_MINUTES = 60

DB_PATH = os.path.join(os.path.dirname(__file__), 'techbank_secure.db')

# ==================== FIX 4b: RATE LIMITER ====================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def init_db():
    """Initialize secure database — passwords stored as bcrypt hashes"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL DEFAULT 1000.00,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_acct INTEGER NOT NULL,
        to_acct INTEGER NOT NULL,
        amount REAL NOT NULL,
        note TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_acct) REFERENCES accounts(id),
        FOREIGN KEY(to_acct) REFERENCES accounts(id)
    )''')

    # FIX 5: Store bcrypt-hashed passwords (12 rounds)
    test_users = [
        ('admin', 'admin123', 'admin'),
        ('user1', 'user1pass', 'user'),
        ('user2', 'user2pass', 'user'),
    ]
    for username, password, role in test_users:
        existing = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not existing:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, hashed.decode('utf-8'), role)
            )

    # Create accounts for seeded users
    for username in ['admin', 'user1', 'user2']:
        user = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if user:
            acct_num = f"ACC{'00' if username == 'admin' else ('01' if username == 'user1' else '02')}1"
            balance = 5000.00 if username == 'admin' else 3000.00
            existing = c.execute("SELECT id FROM accounts WHERE user_id=?", (user[0],)).fetchone()
            if not existing:
                c.execute(
                    "INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,?)",
                    (user[0], acct_num, balance)
                )

    conn.commit()
    conn.close()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ==================== FIX 6c: SECURITY HEADERS ====================
@app.after_request
def set_security_headers(response):
    """Apply security headers to every response."""
    # FIX 2b: Content Security Policy — blocks inline scripts
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# ==================== FIX 3: CSRF TOKEN HELPERS ====================
def generate_csrf_token():
    """Generate and store a per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token():
    """Validate submitted CSRF token against session token."""
    token = request.form.get('csrf_token', '')
    session_token = session.get('csrf_token', '')
    if not session_token or not hmac.compare_digest(token, session_token):
        return False
    return True


app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ==================== FIX 4: AUTHORIZATION DECORATOR ====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return render_template('403.html'), 403
        return f(*args, **kwargs)
    return decorated


# ===================== ROUTES =====================

@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ==================== FIX 1: PARAMETERIZED LOGIN ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    SECURE — Fix 1: Parameterized query prevents SQL injection.
    Fix 5: bcrypt password verification.
    Fix 3: CSRF token validated.
    """
    if request.method == 'POST':
        # FIX 3: Validate CSRF token first
        if not validate_csrf_token():
            return render_template('login.html', error='Invalid request. Please try again.'), 403

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Basic input validation
        if not username or not password:
            return render_template('login.html', error='Username and password required.')

        conn = get_db_connection()
        # FIX 1: Parameterized query — no string concatenation
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        # FIX 5: bcrypt hash comparison
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session.clear()                         # Prevent session fixation
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True                # Apply 15-min timeout
            return redirect(url_for('dashboard'))
        else:
            time.sleep(0.3)  # Timing-safe delay to prevent enumeration
            return render_template('login.html', error='Invalid credentials.')

    return render_template('login.html')


# ==================== FIX 2: OUTPUT ENCODING IN SEARCH ====================
@app.route('/search')
@login_required
def search():
    """
    SECURE — Fix 2: escape() encodes all user input before rendering.
    Jinja2 auto-escaping also active (no | safe filter used).
    """
    query = request.args.get('q', '')
    # FIX 2: markupsafe.escape() encodes <, >, &, ", ' — XSS neutralized
    safe_query = escape(query)
    return render_template('search.html', query=safe_query)


# ==================== FIX 2+3: STORED XSS + CSRF ON TRANSFER ====================
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    """
    SECURE — Fix 2: note stored raw but rendered with Jinja2 auto-escaping (no | safe).
    Fix 3: CSRF token required and validated.
    """
    if request.method == 'POST':
        # FIX 3: Validate CSRF token
        if not validate_csrf_token():
            return render_template('transfer.html', error='Invalid request (CSRF).'), 403

        to_account = request.form.get('to_account', '')
        note = request.form.get('note', '')

        # Input validation
        try:
            amount = float(request.form.get('amount', 0))
            if amount <= 0:
                raise ValueError()
        except ValueError:
            return render_template('transfer.html', error='Invalid amount.')

        if len(note) > 500:
            return render_template('transfer.html', error='Note too long (max 500 chars).')

        conn = get_db_connection()

        # FIX 4: Only get accounts owned by the current user
        user_account = conn.execute(
            "SELECT id, balance FROM accounts WHERE user_id = ?",
            (session['user_id'],)
        ).fetchone()

        if not user_account:
            conn.close()
            return render_template('transfer.html', error='No account found.')

        if user_account['balance'] < amount:
            conn.close()
            return render_template('transfer.html', error='Insufficient balance.')

        # Validate target account exists
        target = conn.execute(
            "SELECT id FROM accounts WHERE id = ?", (to_account,)
        ).fetchone()
        if not target:
            conn.close()
            return render_template('transfer.html', error='Target account not found.')

        from_acct = user_account['id']

        # FIX 2: Note stored as-is; Jinja2 will auto-escape on display (no | safe)
        conn.execute(
            "INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
            (from_acct, int(to_account), amount, note)
        )
        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, from_acct)
        )
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, int(to_account))
        )
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    accounts = conn.execute(
        "SELECT id, account_number FROM accounts WHERE user_id != ?",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('transfer.html', accounts=accounts)


# ==================== FIX 4: AUTHORIZATION CHECK ON ACCOUNT VIEW ====================
@app.route('/account/<int:account_id>')
@login_required
def view_account(account_id):
    """
    SECURE — Fix 4: Account ownership verified before returning data.
    Returns 403 if account belongs to another user.
    """
    conn = get_db_connection()

    # FIX 4: Check that account belongs to the logged-in user
    account = conn.execute(
        "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
        (account_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not account:
        return render_template('403.html'), 403  # Forbidden — not their account

    return render_template('account.html', account=account)


# ==================== FIX 5: BCRYPT REGISTRATION ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    SECURE — Fix 5: bcrypt hashing with 12 rounds.
    Fix 3: CSRF token validated.
    """
    if request.method == 'POST':
        # FIX 3: Validate CSRF token
        if not validate_csrf_token():
            return render_template('register.html', error='Invalid request.'), 403

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Input validation
        if not username or not password:
            return render_template('register.html', error='All fields required.')
        if len(username) < 3 or len(username) > 30:
            return render_template('register.html', error='Username must be 3–30 characters.')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return render_template('register.html', error='Username: alphanumeric and underscore only.')
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters.')

        # FIX 5: Hash password with bcrypt (12 rounds)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, password_hash.decode('utf-8'), 'user')
            )
            user_id = conn.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()['id']
            conn.execute(
                "INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,?)",
                (user_id, f'ACC{user_id:03d}', 1000.00)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    accounts = conn.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session['user_id'],)
    ).fetchall()
    transactions = conn.execute(
        """SELECT * FROM transactions
           WHERE from_acct IN (SELECT id FROM accounts WHERE user_id = ?)
           ORDER BY timestamp DESC LIMIT 10""",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('dashboard.html',
                           accounts=accounts,
                           transactions=transactions,
                           username=session.get('username'))


@app.route('/transactions')
@login_required
def transactions():
    conn = get_db_connection()
    accounts = conn.execute(
        "SELECT id FROM accounts WHERE user_id = ?", (session['user_id'],)
    ).fetchall()
    account_ids = [acc['id'] for acc in accounts]

    if not account_ids:
        transactions_list = []
    else:
        placeholders = ','.join('?' * len(account_ids))
        query = f"""SELECT * FROM transactions
                    WHERE from_acct IN ({placeholders}) OR to_acct IN ({placeholders})
                    ORDER BY timestamp DESC"""
        transactions_list = conn.execute(query, account_ids + account_ids).fetchall()

    conn.close()
    return render_template('transactions.html', transactions=transactions_list)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ===================================================================
# TASK 4: SECURE REST API  (JWT + Rate Limiting + Input Validation)
# ===================================================================

try:
    from marshmallow import Schema, fields, validate, ValidationError
    MARSHMALLOW_AVAILABLE = True
except ImportError:
    MARSHMALLOW_AVAILABLE = False


# --- Marshmallow Schemas (input validation) ---
if MARSHMALLOW_AVAILABLE:
    class LoginSchema(Schema):
        username = fields.Str(required=True, validate=validate.Length(min=1, max=50))
        password = fields.Str(required=True, validate=validate.Length(min=1, max=100))

    class TransferSchema(Schema):
        to_account = fields.Int(required=True, validate=validate.Range(min=1))
        amount = fields.Float(required=True, validate=validate.Range(min=0.01, max=1_000_000))
        note = fields.Str(load_default='', validate=validate.Length(max=500))


def create_jwt(user_id, username, role):
    payload = {
        'sub': str(user_id),
        'username': username,
        'role': role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def jwt_required(f):
    """Middleware: validate JWT on every API request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth_header.split(' ', 1)[1]
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            g.jwt_user = payload
        except pyjwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except pyjwt.InvalidTokenError as e:
            return jsonify({'error': 'Invalid token', 'detail': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Token error', 'detail': str(e)}), 401
        return f(*args, **kwargs)
    return decorated


def api_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.jwt_user.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# 4.0 — Unprotected validation endpoint (for testing input validation / 422 responses)
@app.route('/api/validate-transfer', methods=['POST'])
def api_validate_transfer():
    """Test endpoint — validates transfer input, no auth required. For screenshot/demo only."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    if MARSHMALLOW_AVAILABLE:
        try:
            data = TransferSchema().load(data)
        except ValidationError as e:
            return jsonify({'error': 'Validation failed', 'details': e.messages}), 422
    return jsonify({'message': 'Input valid'}), 200


# 4.1a — Token endpoint (rate-limited: 5/min/IP)
@app.route('/api/auth/token', methods=['POST'])
@limiter.limit("5 per minute")
def api_auth_token():
    """Issue JWT on valid credentials. Rate-limited to 5 attempts/min/IP."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    if MARSHMALLOW_AVAILABLE:
        try:
            data = LoginSchema().load(data)
        except ValidationError as e:
            return jsonify({'error': 'Validation failed', 'details': e.messages}), 422

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        token = create_jwt(user['id'], user['username'], user['role'])
        return jsonify({
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': JWT_EXPIRY_MINUTES * 60,
        })
    else:
        time.sleep(0.3)
        return jsonify({'error': 'Invalid credentials'}), 401


# 4.1b — Protected user info endpoint
@app.route('/api/me')
@jwt_required
def api_me():
    """Return current authenticated user's info."""
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (g.jwt_user['sub'],)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': user['id'], 'username': user['username'], 'role': user['role']})


# 4.1c — Admin-only: list all users
@app.route('/api/admin/users')
@jwt_required
@api_admin_required
def api_admin_users():
    """Admin-only endpoint: list all users."""
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


# 4.2 — Secure transfer via API
@app.route('/api/transfer', methods=['POST'])
@jwt_required
@limiter.limit("20 per minute")
def api_transfer():
    """JWT-authenticated fund transfer with full input validation."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    if MARSHMALLOW_AVAILABLE:
        try:
            data = TransferSchema().load(data)
        except ValidationError as e:
            return jsonify({'error': 'Validation failed', 'details': e.messages}), 422

    user_id = g.jwt_user['sub']
    to_account = data.get('to_account')
    amount = data.get('amount')
    note = data.get('note', '')

    conn = get_db_connection()
    user_account = conn.execute(
        "SELECT id, balance FROM accounts WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not user_account:
        conn.close()
        return jsonify({'error': 'No account found'}), 404

    if user_account['balance'] < amount:
        conn.close()
        return jsonify({'error': 'Insufficient balance'}), 400

    target = conn.execute("SELECT id FROM accounts WHERE id = ?", (to_account,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'Target account not found'}), 404

    from_acct = user_account['id']
    conn.execute(
        "INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
        (from_acct, to_account, amount, note)
    )
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, from_acct))
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, to_account))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Transfer successful', 'amount': amount}), 200


# --- Error handlers ---
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    init_db()
    # debug=False in secure version
    app.run(debug=False, host='127.0.0.1', port=5001)
