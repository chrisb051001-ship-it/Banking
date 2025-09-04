"""
United Empire Federal Reserve Banking (UEFRB)
A Flask web app for roleplay banking with accounts, unique UIDs, username display, live UID validation, and admin deposits. Currency is UED ($) only.

Quick start
-----------
1) Create a virtual env and install deps:
   python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
   pip install flask python-dotenv

2) Set environment variables (optional but recommended):
   export FLASK_ENV=development
   export SECRET_KEY="change-this"
   export ADMIN_KEY="super-secret-admin-key"

3) Run it:
   python app.py
   Open http://127.0.0.1:5000

Notes
-----
- Currency: UED with $ symbol only. Amounts stored in integer cents.
- Unique account IDs look like UE-XXXXXXXX (base36).
- Admin deposits require ADMIN_KEY (header X-Admin-Key or form field admin_key).
- Minimal demo: for production add CSRF, HTTPS, stronger auth, rate-limits, audit, etc.
"""

import os
import sqlite3
import secrets
import string
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Optional

from flask import (
    Flask, g, render_template_string, request, redirect, url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_TITLE = "United Empire Federal Reserve Banking"
DB_PATH = os.environ.get("UEFRB_DB", "uefrb.sqlite3")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -----------------------------
# Database helpers
# -----------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    pin_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,                 -- 'DEPOSIT', 'TRANSFER_OUT', 'TRANSFER_IN', 'ADJUSTMENT'
    from_uid TEXT,
    to_uid TEXT,
    amount_cents INTEGER NOT NULL,
    memo TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid);
CREATE INDEX IF NOT EXISTS idx_tx_ts ON transactions(ts);
"""


def init_db():
    db = get_db()
    for stmt in SCHEMA_SQL.split(";\n"):
        s = stmt.strip()
        if s:
            db.execute(s)
    db.commit()


@app.before_request
def ensure_db():
    init_db()

# -----------------------------
# Utilities
# -----------------------------

def base36(n: int) -> str:
    digits = string.digits + string.ascii_uppercase
    if n == 0:
        return "0"
    s = []
    neg = n < 0
    n = abs(n)
    while n:
        n, r = divmod(n, 36)
        s.append(digits[r])
    if neg:
        s.append("-")
    return "".join(reversed(s))


def generate_uid(db: sqlite3.Connection) -> str:
    while True:
        rand = secrets.randbits(40)  # ~1e12 range
        uid = f"UE-{base36(rand)[:8]}"  # UE-XXXXXXXX
        exists = db.execute("SELECT 1 FROM users WHERE uid = ?", (uid,)).fetchone()
        if not exists:
            return uid


def to_cents(amount_str: str) -> Optional[int]:
    try:
        amt = (Decimal(amount_str).quantize(Decimal("0.01")))
        cents = int(amt * 100)
        if cents < 0:
            return None
        return cents
    except (InvalidOperation, TypeError):
        return None


def format_usd(cents: int) -> str:
    return f"${cents / 100:,.2f}"


def current_user() -> Optional[sqlite3.Row]:
    uid = session.get("user_uid")
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
    return user


def get_username(uid: Optional[str]) -> Optional[str]:
    if not uid:
        return None
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE uid = ?", (uid,)).fetchone()
    return row[0] if row else None


def resolve_user(ref: str) -> Optional[sqlite3.Row]:
    """Find a user by UID (UE-XXXX) or by exact username."""
    db = get_db()
    if ref.upper().startswith("UE-"):
        return db.execute("SELECT * FROM users WHERE uid = ?", (ref.strip(),)).fetchone()
    return db.execute("SELECT * FROM users WHERE username = ?", (ref.strip(),)).fetchone()


# -----------------------------
# HTML templates (inline)
# -----------------------------
LAYOUT = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{{ title }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 1.25rem; max-width: 820px; box-shadow: 0 4px 12px rgba(0,0,0,.06); }
    .row { display: flex; gap: 1rem; flex-wrap: wrap; }
    .row > * { flex: 1 1 320px; }
    input, button { padding: .6rem .8rem; border-radius: 10px; border: 1px solid #ccc; width: 100%; }
    button { cursor: pointer; }
    nav a { margin-right: 1rem; }
    .muted { color: #666; }
    .success { color: #176e3d; }
    .error { color: #a31717; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: .5rem; border-bottom: 1px solid #eee; font-size: .95rem; text-align: left; }
    .right { text-align: right; }
    .inline { display:flex; gap:.5rem; align-items:center; }
    small { color:#555; }
  </style>
</head>
<body>
  <h1>{{ app_title }}</h1>
  <nav>
    {% if user %}
      <strong>Logged in as:</strong> {{ user["username"] }} ({{ user["uid"] }})
      <a href=\"{{ url_for('dashboard') }}\">Dashboard</a>
      <a href=\"{{ url_for('logout') }}\">Logout</a>
    {% else %}
      <a href=\"{{ url_for('index') }}\">Home</a>
      <a href=\"{{ url_for('register') }}\">Register</a>
      <a href=\"{{ url_for('login') }}\">Login</a>
    {% endif %}
    <a href=\"{{ url_for('admin_panel') }}\" style=\"margin-left:1rem\">Admin</a>
  </nav>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <ul>
        {% for category, message in messages %}
          <li class=\"{{ category }}\">{{ message }}</li>
        {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}
  <div class=\"card\">
    {% block content %}{% endblock %}
  </div>
  <script>
    // Live lookup for recipient username by UID
    async function lookupUID(inputId, displayId){
      const v = document.getElementById(inputId).value.trim();
      const target = document.getElementById(displayId);
      if (!v) { target.textContent = '\u2014'; return; }
      try {
        const resp = await fetch(`/api/lookup?uid=${encodeURIComponent(v)}`);
        if (!resp.ok) { target.textContent = 'Invalid / not found'; return; }
        const data = await resp.json();
        target.textContent = data.username ? `${data.username} (${data.uid})` : 'Invalid / not found';
      } catch(e){ target.textContent = 'Error'; }
    }
  </script>
</body>
</html>
"""

INDEX_TPL = """
{% extends 'layout' %}
{% block content %}
  <h2>Welcome to the UE Federal Reserve Banking</h2>
  <p class=\"muted\">Create an account, share your <strong>UID</strong> with other players, and transfer funds securely for your roleplay group.</p>
  <div class=\"row\">
    <div>
      <h3>Create Account</h3>
      <form action=\"{{ url_for('register') }}\" method=\"post\">
        <input name=\"username\" placeholder=\"Username\" required />
        <input name=\"pin\" placeholder=\"4-8 digit PIN\" minlength=\"4\" maxlength=\"8\" required />
        <button>Create</button>
      </form>
    </div>
    <div>
      <h3>Login</h3>
      <form action=\"{{ url_for('login') }}\" method=\"post\">
        <input name=\"username\" placeholder=\"Username\" required />
        <input name=\"pin\" placeholder=\"PIN\" minlength=\"4\" maxlength=\"8\" required />
        <button>Login</button>
      </form>
    </div>
  </div>
{% endblock %}
"""

DASHBOARD_TPL = """
{% extends 'layout' %}
{% block content %}
  <h2>Account Dashboard</h2>
  <p><strong>Account Holder:</strong> {{ user["username"] }} ({{ user["uid"] }})</p>
  <p><strong>Balance:</strong> {{ format_usd(balance_cents) }}</p>

  <h3>Transfer Funds</h3>
  <form action=\"{{ url_for('transfer') }}\" method=\"post\">
    <label>Recipient UID</label>
    <input id=\"to_uid\" name=\"to_uid\" placeholder=\"e.g., UE-1AB2C3D4\" oninput=\"lookupUID('to_uid','recipient_name')\" required />
    <small>Recipient: <strong id=\"recipient_name\">\u2014</strong></small>
    <br><br>
    <input name=\"amount\" placeholder=\"Amount (e.g., 25.00)\" required />
    <input name=\"memo\" placeholder=\"Memo (optional)\" />
    <button>Send</button>
  </form>

  <h3>Recent Transactions</h3>
  <table>
    <thead>
      <tr><th>Time</th><th>Type</th><th>From</th><th>To</th><th class=\"right\">Amount</th><th>Memo</th></tr>
    </thead>
    <tbody>
      {% for tx in txs %}
        <tr>
          <td>{{ tx['ts'] }}</td>
          <td>{{ tx['type'] }}</td>
          <td>{{ tx['from_display'] or '-' }}</td>
          <td>{{ tx['to_display'] or '-' }}</td>
          <td class=\"right\">{{ format_usd(tx['amount_cents']) }}</td>
          <td>{{ tx['memo'] or '' }}</td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
{% endblock %}
"""

REGISTER_TPL = """
{% extends 'layout' %}
{% block content %}
  <h2>Create Account</h2>
  <form method=\"post\">
    <input name=\"username\" placeholder=\"Username\" required />
    <input name=\"pin\" placeholder=\"4-8 digit PIN\" minlength=\"4\" maxlength=\"8\" required />
    <button>Create</button>
  </form>
{% endblock %}
"""

LOGIN_TPL = """
{% extends 'layout' %}
{% block content %}
  <h2>Login</h2>
  <form method=\"post\">
    <input name=\"username\" placeholder=\"Username\" required />
    <input name=\"pin\" placeholder=\"PIN\" minlength=\"4\" maxlength=\"8\" required />
    <button>Login</button>
  </form>
{% endblock %}
"""

ADMIN_TPL = """
{% extends 'layout' %}
{% block content %}
  <h2>Admin: Deposit / Lookup</h2>
  <form action=\"{{ url_for('admin_deposit') }}\" method=\"post\">
    <input name=\"admin_key\" placeholder=\"Admin Key\" required />
    <input name=\"to_ref\" placeholder=\"Target Username or UID\" required />
    <input name=\"amount\" placeholder=\"Amount (e.g., 100.00)\" required />
    <input name=\"memo\" placeholder=\"Memo (optional)\" />
    <button>Deposit</button>
  </form>
  <p class=\"muted\">Tip: You can enter either <strong>Username</strong> or <strong>UID</strong>. The confirmation will show both.</p>
  <hr>
  <h3>Quick Lookup</h3>
  <div class=\"inline\">
    <input id=\"lookupRef\" placeholder=\"Username or UID\" oninput=\"lookupUID('lookupRef','lookupDisp')\">
    <span id=\"lookupDisp\">\u2014</span>
  </div>
{% endblock %}
"""

# Register templates with Flask's loader
app.jinja_loader.mapping = {
    'layout': LAYOUT,
    'index.html': INDEX_TPL,
    'dashboard.html': DASHBOARD_TPL,
    'register.html': REGISTER_TPL,
    'login.html': LOGIN_TPL,
    'admin.html': ADMIN_TPL,
}

# Allow using format_usd in templates
@app.context_processor
def inject_helpers():
    return dict(format_usd=format_usd)

# -----------------------------
# Routes
# -----------------------------

@app.route("/")
def index():
    user = current_user()
    if user:
        return redirect(url_for("dashboard"))
    return render_template_string(INDEX_TPL, title=APP_TITLE, app_title=APP_TITLE, user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pin = request.form.get("pin", "").strip()
        if not (username and pin.isdigit() and 4 <= len(pin) <= 8):
            flash("Invalid username or PIN.", "error")
            return redirect(url_for("register"))
        db = get_db()
        uid = generate_uid(db)
        try:
            db.execute(
                "INSERT INTO users(uid, username, pin_hash, created_at) VALUES(?,?,?,?)",
                (uid, username, generate_password_hash(pin), datetime.utcnow().isoformat()),
            )
            user_id = db.execute("SELECT id FROM users WHERE uid = ?", (uid,)).fetchone()[0]
            db.execute("INSERT INTO accounts(user_id, balance_cents) VALUES(?, 0)", (user_id,))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already taken.", "error")
            return redirect(url_for("register"))
        session["user_uid"] = uid
        flash(f"Account created. Your UID is {uid}.", "success")
        return redirect(url_for("dashboard"))
    return render_template_string(REGISTER_TPL, title=APP_TITLE, app_title=APP_TITLE, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        pin = request.form.get("pin", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["pin_hash"], pin):
            session["user_uid"] = user["uid"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
        return redirect(url_for("login"))
    return render_template_string(LOGIN_TPL, title=APP_TITLE, app_title=APP_TITLE, user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


def get_balance(uid: str) -> int:
    db = get_db()
    row = db.execute(
        "SELECT a.balance_cents FROM accounts a JOIN users u ON a.user_id = u.id WHERE u.uid = ?",
        (uid,),
    ).fetchone()
    return int(row[0]) if row else 0


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    balance_cents = get_balance(user["uid"])

    # Fetch recent transactions and enrich with usernames
    db = get_db()
    txs_raw = db.execute(
        """
        SELECT * FROM transactions
        WHERE from_uid = ? OR to_uid = ?
        ORDER BY ts DESC LIMIT 20
        """,
        (user["uid"], user["uid"]),
    ).fetchall()

    def display(uid: Optional[str]) -> Optional[str]:
        if not uid:
            return None
        uname = get_username(uid)
        return f"{uname} ({uid})" if uname else uid

    txs = []
    for t in txs_raw:
        txs.append({
            **dict(t),
            "from_display": display(t["from_uid"]),
            "to_display": display(t["to_uid"]),
        })

    return render_template_string(
        DASHBOARD_TPL,
        title=APP_TITLE,
        app_title=APP_TITLE,
        user=user,
        balance_cents=balance_cents,
        txs=txs,
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    user = current_user()
    if not user:
        flash("Please log in.", "error")
        return redirect(url_for("login"))
    to_uid = request.form.get("to_uid", "").strip()
    amount_str = request.form.get("amount", "").strip()
    memo = request.form.get("memo", "").strip() or None

    cents = to_cents(amount_str)
    if cents is None or cents == 0:
        flash("Invalid amount.", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    recipient = db.execute("SELECT * FROM users WHERE uid = ?", (to_uid,)).fetchone()
    if not recipient:
        flash("Incorrect ID number.", "error")
        return redirect(url_for("dashboard"))

    # Atomic transfer
    try:
        db.execute("BEGIN IMMEDIATE")
        bal_from = get_balance(user["uid"])
        if bal_from < cents:
            db.execute("ROLLBACK")
            flash("Insufficient funds.", "error")
            return redirect(url_for("dashboard"))
        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?",
            (cents, user["id"]),
        )
        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?",
            (cents, recipient["id"]),
        )
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "TRANSFER_OUT", user["uid"], recipient["uid"], cents, memo),
        )
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "TRANSFER_IN", user["uid"], recipient["uid"], cents, memo),
        )
        db.commit()
        flash(f"Transfer completed: {format_usd(cents)} sent to {recipient['username']} ({recipient['uid']}).", "success")
    except Exception as e:
        db.execute("ROLLBACK")
        flash(f"Transfer failed: {e}", "error")
    return redirect(url_for("dashboard"))


# Admin deposit (accepts Username OR UID)
@app.route("/admin", methods=["GET"]) 
def admin_panel():
    return render_template_string(ADMIN_TPL, title=APP_TITLE, app_title=APP_TITLE, user=current_user())


@app.route("/admin/deposit", methods=["POST"]) 
def admin_deposit():
    key = request.form.get("admin_key") or request.headers.get("X-Admin-Key")
    if key != ADMIN_KEY:
        flash("Unauthorized.", "error")
        return redirect(url_for("admin_panel"))

    to_ref = request.form.get("to_ref", "").strip()
    amount_str = request.form.get("amount", "").strip()
    memo = request.form.get("memo", "").strip() or "Admin deposit"

    cents = to_cents(amount_str)
    if cents is None or cents == 0:
        flash("Invalid amount.", "error")
        return redirect(url_for("admin_panel"))

    user = resolve_user(to_ref)
    if not user:
        flash("Target not found.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?",
            (cents, user["id"]),
        )
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "DEPOSIT", None, user["uid"], cents, memo),
        )
        db.commit()
        flash(f"Deposit successful: {format_usd(cents)} added to {user['username']} ({user['uid']}).", "success")
    except Exception as e:
        db.execute("ROLLBACK")
        flash(f"Deposit failed: {e}", "error")

    return redirect(url_for("admin_panel"))


# -----------------------------
# Minimal JSON API (with lookup)
# -----------------------------
@app.get("/api/lookup")
def api_lookup():
    uid = request.args.get("uid", "").strip()
    if not uid:
        return jsonify({"error": "missing_uid"}), 400
    db = get_db()
    user = db.execute("SELECT uid, username FROM users WHERE uid = ?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"uid": user["uid"], "username": user["username"]})


@app.post("/api/register")
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    pin = (data.get("pin") or "").strip()
    if not (username and pin.isdigit() and 4 <= len(pin) <= 8):
        return jsonify({"error": "invalid_input"}), 400
    db = get_db()
    uid = generate_uid(db)
    try:
        db.execute(
            "INSERT INTO users(uid, username, pin_hash, created_at) VALUES(?,?,?,?)",
            (uid, username, generate_password_hash(pin), datetime.utcnow().isoformat()),
        )
        user_id = db.execute("SELECT id FROM users WHERE uid = ?", (uid,)).fetchone()[0]
        db.execute("INSERT INTO accounts(user_id, balance_cents) VALUES(?, 0)", (user_id,))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username_taken"}), 409
    return jsonify({"uid": uid, "username": username}), 201


@app.post("/api/transfer")
def api_transfer():
    data = request.get_json(force=True, silent=True) or {}
    from_uid = (data.get("from_uid") or "").strip()
    pin = (data.get("pin") or "").strip()
    to_uid = (data.get("to_uid") or "").strip()
    amount_str = (data.get("amount") or "").strip()
    memo = (data.get("memo") or None)

    cents = to_cents(amount_str)
    if cents is None or cents == 0:
        return jsonify({"error": "invalid_amount"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uid = ?", (from_uid,)).fetchone()
    if not user or not check_password_hash(user["pin_hash"], pin):
        return jsonify({"error": "auth_failed"}), 401
    recipient = db.execute("SELECT * FROM users WHERE uid = ?", (to_uid,)).fetchone()
    if not recipient:
        return jsonify({"error": "incorrect_id_number"}), 404

    try:
        db.execute("BEGIN IMMEDIATE")
        bal_from = get_balance(from_uid)
        if bal_from < cents:
            db.execute("ROLLBACK")
            return jsonify({"error": "insufficient_funds"}), 400
        db.execute("UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?", (cents, user["id"]))
        db.execute("UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?", (cents, recipient["id"]))
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "TRANSFER_OUT", from_uid, to_uid, cents, memo),
        )
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "TRANSFER_IN", from_uid, to_uid, cents, memo),
        )
        db.commit()
        return jsonify({
            "status": "ok",
            "from": {"username": user["username"], "uid": user["uid"]},
            "to": {"username": recipient["username"], "uid": recipient["uid"]},
            "amount": format_usd(cents),
            "timestamp": now,
        }), 200
    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({"error": "transfer_failed", "detail": str(e)}), 500


@app.post("/api/admin/deposit")
def api_admin_deposit():
    key = request.headers.get("X-Admin-Key") or (request.get_json(silent=True) or {}).get("admin_key")
    if key != ADMIN_KEY:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    to_ref = (data.get("to_ref") or data.get("to_uid") or data.get("username") or "").strip()
    amount_str = (data.get("amount") or "").strip()
    memo = (data.get("memo") or "Admin deposit")

    cents = to_cents(amount_str)
    if cents is None or cents == 0:
        return jsonify({"error": "invalid_amount"}), 400

    user = resolve_user(to_ref)
    if not user:
        return jsonify({"error": "target_not_found"}), 404

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?", (cents, user["id"]))
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO transactions(ts, type, from_uid, to_uid, amount_cents, memo) VALUES(?,?,?,?,?,?)",
            (now, "DEPOSIT", None, user["uid"], cents, memo),
        )
        db.commit()
        return jsonify({
            "status": "ok",
            "to": {"username": user["username"], "uid": user["uid"]},
            "amount": format_usd(cents),
            "timestamp": now
        }), 200
    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({"error": "deposit_failed", "detail": str(e)}), 500


# Health check
@app.get("/api/health")
def api_health():
    return {"status": "ok", "title": APP_TITLE}


if __name__ == "__main__":
    app.run(debug=True)
