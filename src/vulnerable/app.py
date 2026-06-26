"""
8TechBank Vulnerable Application
This version contains 6 deliberately vulnerable code patterns for security assessment
WARNING: This is intentionally vulnerable - do NOT use in production
"""

from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_123'  # VULNERABLE: Hardcoded secret key

# Database configuration
DB_PATH = 'techbank.db'

def init_db():
    """Initialize the database with vulnerable schema"""
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Create users table - VULNERABLE: passwords stored in plaintext
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        
        # Create accounts table
        c.execute('''CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 1000.00,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        # Create transactions table - VULNERABLE: no sanitization on notes
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
        
        # Insert test users - VULNERABLE: plaintext passwords
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  ('admin', 'admin123'))
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  ('user1', 'user1pass'))
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  ('user2', 'user2pass'))
        
        # Create accounts for users
        c.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                  (1, 'ACC001', 5000.00))
        c.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                  (2, 'ACC002', 3000.00))
        c.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
                  (3, 'ACC003', 2500.00))
        
        conn.commit()
        conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==================== PATTERN 1: SQL INJECTION IN LOGIN ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABLE - SQL Injection (CWE-89)
    Uses string concatenation in SQL query with user input
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: String concatenation in SQL query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        conn = get_db_connection()
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

# ==================== PATTERN 2: REFLECTED XSS IN SEARCH ====================
@app.route('/search')
def search():
    """
    VULNERABLE - Reflected XSS (CWE-79)
    User input rendered without encoding
    """
    query = request.args.get('q', '')
    
    # VULNERABLE: User input directly rendered in HTML without encoding
    results_html = f"<h2>Search Results for: {query}</h2><p>No results found.</p>"
    
    return render_template('search.html', results=results_html)

# ==================== PATTERN 3: STORED XSS IN TRANSACTION NOTES ====================
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """
    VULNERABLE - Stored XSS (CWE-79)
    User-supplied note stored and rendered raw without sanitization
    """
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        to_account = request.form['to_account']
        amount = float(request.form['amount'])
        note = request.form.get('note', '')  # VULNERABLE: No sanitization
        
        conn = get_db_connection()
        
        # Get sender's account
        user_accounts = conn.execute(
            "SELECT id FROM accounts WHERE user_id = ?", 
            (session['user_id'],)
        ).fetchall()
        
        if not user_accounts:
            conn.close()
            return render_template('transfer.html', error='No account found')
        
        from_acct = user_accounts[0]['id']
        
        # Check balance
        balance = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", 
            (from_acct,)
        ).fetchone()
        
        if balance['balance'] < amount:
            conn.close()
            return render_template('transfer.html', error='Insufficient balance')
        
        # Execute transfer with unsanitized note
        conn.execute(
            "INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
            (from_acct, to_account, amount, note)  # VULNERABLE: note not sanitized
        )
        
        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, from_acct)
        )
        
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, to_account)
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

# ==================== PATTERN 4: BROKEN ACCESS CONTROL (IDOR) ====================
@app.route('/account/<int:account_id>')
def view_account(account_id):
    """
    VULNERABLE - Insecure Direct Object Reference (CWE-639)
    No authorization check - any authenticated user can view ANY account
    """
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # VULNERABLE: No check if account belongs to current user
    account = conn.execute(
        "SELECT * FROM accounts WHERE id = ?", 
        (account_id,)
    ).fetchone()
    
    conn.close()
    
    if not account:
        return "Account not found", 404
    
    # VULNERABLE: Returns ANY account without authorization
    return render_template('account.html', account=account)

# ==================== PATTERN 5: PLAINTEXT PASSWORD STORAGE ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    VULNERABLE - Plaintext Password Storage (CWE-256)
    Passwords stored directly without hashing
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            
            # VULNERABLE: Passwords stored in plaintext
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?,?)",
                (username, password)  # NO HASHING!
            )
            
            # Create default account for new user
            user_id = conn.lastrowid
            conn.execute(
                "INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,?)",
                (user_id, f'ACC{user_id:03d}', 1000.00)
            )
            
            conn.commit()
            conn.close()
            
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

# ==================== PATTERN 6: MISSING CSRF PROTECTION ====================
@app.route('/dashboard')
def dashboard():
    """Dashboard showing user accounts and transactions"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    accounts = conn.execute(
        "SELECT * FROM accounts WHERE user_id = ?",
        (session['user_id'],)
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
def transactions():
    """View all transactions for user accounts"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    accounts = conn.execute(
        "SELECT id FROM accounts WHERE user_id = ?",
        (session['user_id'],)
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
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Home page"""
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)
