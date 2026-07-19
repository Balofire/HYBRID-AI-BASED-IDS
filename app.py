from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from predict import predict_traffic
from flask_bcrypt import Bcrypt
import sqlite3
import random
import os
import string

app = Flask(__name__)
app.secret_key = "ids_demo_secret_key_2024"
bcrypt = Bcrypt(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# ── Demo wallet state (per-session via session dict) ─────────────────
DEFAULT_BALANCE = 50000.00

# ── Login attempt tracker (brute-force simulation) ───────────────────
login_attempts = {}


# ════════════════════════════════════════════════════════════════════
#  DATABASE
# ════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create users table if it doesn't exist."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                username       TEXT    NOT NULL UNIQUE,
                password       TEXT    NOT NULL,
                account_number TEXT    NOT NULL UNIQUE,
                balance        REAL    NOT NULL DEFAULT 50000.00,
                created        DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def generate_account_number(conn):
    """Generate a unique 10-digit account number in format SB-XXXXXXXXXX."""
    while True:
        digits = ''.join(random.choices(string.digits, k=10))
        acct   = f"SB-{digits}"
        exists = conn.execute(
            "SELECT id FROM users WHERE account_number = ?", (acct,)
        ).fetchone()
        if not exists:
            return acct


# ════════════════════════════════════════════════════════════════════
#  TRAFFIC HELPERS
# ════════════════════════════════════════════════════════════════════

def _normal_traffic():
    return {
        "fwd_packet_length_max": 1460,
        "fwd_packet_length_mean": 512,
        "subflow_fwd_bytes": 2048,
        "packet_length_mean": 400,
        "average_packet_size": 420,
        "psh_flag_count": 1,
        "total_length_fwd_packets": 3000,
        "packet_length_variance": 5000,
        "bwd_packets_per_s": 20,
        "flow_duration": 500000,
    }


def _brute_force_traffic(attempt_number=1):
    return {
        "fwd_packet_length_max": random.randint(40, 80),
        "fwd_packet_length_mean": random.uniform(40, 60),
        "subflow_fwd_bytes": random.randint(40, 120),
        "packet_length_mean": random.uniform(40, 60),
        "average_packet_size": random.uniform(40, 65),
        "psh_flag_count": random.randint(3, 8),
        "total_length_fwd_packets": random.randint(40, 150),
        "packet_length_variance": random.uniform(10, 200),
        "bwd_packets_per_s": random.uniform(800, 2000) * attempt_number,
        "flow_duration": random.randint(1000, 8000),
    }


def _dos_traffic():
    return {
        "fwd_packet_length_max": random.randint(50, 100),
        "fwd_packet_length_mean": random.uniform(50, 80),
        "subflow_fwd_bytes": random.randint(50000, 200000),
        "packet_length_mean": random.uniform(50, 80),
        "average_packet_size": random.uniform(55, 85),
        "psh_flag_count": random.randint(5, 15),
        "total_length_fwd_packets": random.randint(80000, 300000),
        "packet_length_variance": random.uniform(20, 500),
        "bwd_packets_per_s": random.uniform(10000, 50000),
        "flow_duration": random.randint(100, 3000),
    }


def _api_abuse_traffic():
    return {
        "fwd_packet_length_max": random.randint(200, 400),
        "fwd_packet_length_mean": random.uniform(150, 300),
        "subflow_fwd_bytes": random.randint(5000, 20000),
        "packet_length_mean": random.uniform(150, 280),
        "average_packet_size": random.uniform(160, 290),
        "psh_flag_count": random.randint(8, 20),
        "total_length_fwd_packets": random.randint(5000, 25000),
        "packet_length_variance": random.uniform(1000, 8000),
        "bwd_packets_per_s": random.uniform(500, 3000),
        "flow_duration": random.randint(5000, 30000),
    }


def _sql_injection_traffic():
    return {
        "fwd_packet_length_max": random.randint(1200, 1500),
        "fwd_packet_length_mean": random.uniform(900, 1300),
        "subflow_fwd_bytes": random.randint(8000, 20000),
        "packet_length_mean": random.uniform(850, 1200),
        "average_packet_size": random.uniform(860, 1210),
        "psh_flag_count": random.randint(10, 25),
        "total_length_fwd_packets": random.randint(8000, 22000),
        "packet_length_variance": random.uniform(50000, 200000),
        "bwd_packets_per_s": random.uniform(50, 300),
        "flow_duration": random.randint(200000, 900000),
    }


# ════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return redirect(url_for("login"))


# ── LOGIN ────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = request.remote_addr

    # Track attempts per IP for brute-force simulation
    if ip not in login_attempts:
        login_attempts[ip] = 0
    login_attempts[ip] += 1
    attempt_count = login_attempts[ip]

    # IDS traffic check (always runs — simulates brute force detection)
    traffic = _brute_force_traffic(attempt_count)
    ids_result = predict_traffic(traffic)

    # Look up user in DB
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    if user and bcrypt.check_password_hash(user["password"], password):
        session["logged_in"]      = True
        session["username"]       = user["username"]
        session["user_id"]        = user["id"]
        session["balance"]        = user["balance"]
        session["account_number"] = user["account_number"]
        login_attempts[ip]        = 0          # reset on success
        ids_result["login_success"] = True
        ids_result["attempt"]       = attempt_count
        return jsonify(ids_result)

    # Failed login
    ids_result["login_success"] = False
    ids_result["attempt"]       = attempt_count
    ids_result["traffic_data"]  = traffic

    if not user:
        ids_result["reason"] = "user_not_found"
    else:
        ids_result["reason"] = "wrong_password"

    return jsonify(ids_result)


# ── REGISTER ─────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm",  "")

    # Basic validation
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required."})

    if len(username) < 3:
        return jsonify({"success": False, "error": "Username must be at least 3 characters."})

    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."})

    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match."})

    # Check if username already taken
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            return jsonify({"success": False, "error": "Username already taken. Please choose another."})

        # Hash password, generate account number, and insert
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        acct   = generate_account_number(conn)
        conn.execute(
            "INSERT INTO users (username, password, account_number, balance) VALUES (?, ?, ?, ?)",
            (username, hashed, acct, DEFAULT_BALANCE)
        )
        conn.commit()

    return jsonify({"success": True, "username": username, "account_number": acct})


# ── DASHBOARD ────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        balance=session.get("balance", DEFAULT_BALANCE),
        username=session.get("username", "user"),
        account_number=session.get("account_number", "SB-----------")
    )


@app.route("/simulate/dos", methods=["POST"])
def simulate_dos():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    traffic = _dos_traffic()
    result  = predict_traffic(traffic)
    result["attack_type"]  = "DoS Flood"
    result["traffic_data"] = traffic
    return jsonify(result)



@app.route("/transfer-page")
def transfer_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template(
        "airtime.html",
        balance=session.get("balance", DEFAULT_BALANCE),
        account_number=session.get("account_number", "")
    )


# ── TRANSFER ─────────────────────────────────────────────────────────
@app.route("/transfer", methods=["POST"])
def transfer():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    data       = request.json
    amount_raw = str(data.get("amount",    ""))
    recipient  = str(data.get("recipient", ""))
    note       = str(data.get("note",      ""))

    sql_keywords   = ["select", "drop", "insert", "update", "delete",
                      "union", "--", ";", "/*", "*/", "xp_", "exec", "1=1", "or 1"]
    combined_input = (amount_raw + recipient + note).lower()
    has_sql        = any(kw in combined_input for kw in sql_keywords)

    if has_sql:
        traffic = _sql_injection_traffic()
        result  = predict_traffic(traffic)
        result["attack_type"]  = "SQL Injection"
        result["blocked"]      = True
        result["traffic_data"] = traffic
        return jsonify(result)

    try:
        amount = float(amount_raw)
    except ValueError:
        traffic = _sql_injection_traffic()
        result  = predict_traffic(traffic)
        result["attack_type"]  = "Malformed Input"
        result["blocked"]      = True
        result["traffic_data"] = traffic
        return jsonify(result)

    current_balance = session.get("balance", DEFAULT_BALANCE)
    if amount <= 0 or amount > current_balance:
        traffic = _normal_traffic()
        result  = predict_traffic(traffic)
        result["attack_type"]  = "Invalid Amount"
        result["blocked"]      = True
        result["traffic_data"] = traffic
        return jsonify(result)

    # Resolve recipient — accept account number (SB-...) or username
    recipient_info = None
    with get_db() as conn:
        if recipient.upper().startswith("SB-"):
            row = conn.execute(
                "SELECT username, account_number FROM users WHERE account_number = ?",
                (recipient.upper(),)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT username, account_number FROM users WHERE username = ?",
                (recipient,)
            ).fetchone()
        if row:
            recipient_info = {"username": row["username"], "account_number": row["account_number"]}

        # Block transfers to self
        if recipient_info and recipient_info["account_number"] == session.get("account_number"):
            traffic = _normal_traffic()
            result  = predict_traffic(traffic)
            result["attack_type"]  = "Self Transfer"
            result["blocked"]      = True
            result["traffic_data"] = traffic
            result["error_msg"]    = "Cannot transfer to your own account."
            return jsonify(result)

        # Deduct sender, credit recipient if found in DB
        new_balance = current_balance - amount
        session["balance"] = new_balance
        conn.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_balance, session["user_id"])
        )
        if recipient_info:
            conn.execute(
                "UPDATE users SET balance = balance + ? WHERE account_number = ?",
                (amount, recipient_info["account_number"])
            )
        conn.commit()

    traffic = _normal_traffic()
    result  = predict_traffic(traffic)
    result["attack_type"]     = "Normal Transfer"
    result["blocked"]         = False
    result["new_balance"]     = new_balance
    result["traffic_data"]    = traffic
    result["recipient_name"]  = recipient_info["username"] if recipient_info else recipient
    result["recipient_found"] = recipient_info is not None
    return jsonify(result)


# ── MANUAL IDS CONSOLE (4th page) ────────────────────────────────────
@app.route("/ids_manual")
def ids_manual():
    return render_template("ids_manual.html")


# ── ORIGINAL IDS PAGE (legacy redirect) ──────────────────────────────
@app.route("/ids")
def ids_page():
    return redirect(url_for("ids_manual"))


@app.route("/predict", methods=["POST"])
def predict():
    data   = request.json
    result = predict_traffic(data)
    return jsonify(result)


# ── LOGOUT ───────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════════
#  STARTUP
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
