from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from predict import predict_traffic
from rule_engine import (
    check_brute_force, record_failed_login, reset_failed_logins,
    check_dos, run_all_rules
)
from sql_predict import predict_sql_from_fields, is_available as sql_model_available
import sqlite3
import random
import os
import string
import json
import logging
from flask_bcrypt import Bcrypt

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "ids_demo_secret_key_2024"
bcrypt = Bcrypt(app)

DB_PATH      = os.path.join(os.path.dirname(__file__), "users.db")
DEFAULT_BAL  = 50000.00


# ════════════════════════════════════════════════════════════════════
#  DATABASE
# ════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip          TEXT,
                username    TEXT,
                route       TEXT,
                detection   TEXT,
                rule        TEXT,
                message     TEXT,
                raw_input   TEXT
            )
        """)
        conn.commit()


def generate_account_number(conn):
    while True:
        digits = ''.join(random.choices(string.digits, k=10))
        acct   = f"SB-{digits}"
        exists = conn.execute(
            "SELECT id FROM users WHERE account_number = ?", (acct,)
        ).fetchone()
        if not exists:
            return acct


# ════════════════════════════════════════════════════════════════════
#  ATTACK LOGGER
# ════════════════════════════════════════════════════════════════════

def log_attack(ip: str, route: str, detection: str,
               rule: str, message: str, raw_input: str = ""):
    """Persist every detected attack to the attack_log table."""
    username = session.get("username", "anonymous")
    logger.warning(f"ATTACK | {detection} | {rule} | IP={ip} | {message}")
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO attack_log
                   (ip, username, route, detection, rule, message, raw_input)
                   VALUES (?,?,?,?,?,?,?)""",
                (ip, username, route, detection, rule, message, raw_input[:500])
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to write attack log: {e}")


# ════════════════════════════════════════════════════════════════════
#  HYBRID DETECTION  — rule engine  +  SQL-AI  +  traffic IDS
# ════════════════════════════════════════════════════════════════════

def hybrid_check_form(ip: str, endpoint: str,
                      fields: dict,
                      required: list = None,
                      numeric:  list = None) -> dict:
    """
    Runs every detection layer for a form submission.

    Returns a unified result dict:
        blocked        : bool
        detection      : str   — "RULE" | "SQL_AI" | "TRAFFIC_IDS" | "CLEAN"
        rule           : str   — which specific rule fired
        message        : str
        confidence     : float
        traffic_result : dict  — raw output from predict_traffic()
        sql_result     : dict  — raw output from predict_sql_from_fields()
    """
    raw_body = json.dumps(fields)

    # ── Layer 1: Rule engine ─────────────────────────────────────────
    rule_result = run_all_rules(
        ip=ip,
        endpoint=endpoint,
        request_body=raw_body,
        form_fields=fields,
        required_fields=required,
        numeric_fields=numeric,
    )
    if rule_result["flagged"]:
        log_attack(ip, endpoint, "RULE",
                   rule_result["rule"], rule_result["message"], raw_body)
        traffic = _sql_injection_traffic()
        return {
            "blocked":        True,
            "detection":      "RULE",
            "rule":           rule_result["rule"],
            "message":        rule_result["message"],
            "confidence":     1.0,
            "traffic_result": predict_traffic(traffic),
            "sql_result":     {"is_sql": False, "available": False},
            "traffic_data":   traffic,
        }

    # ── Layer 2: SQL-injection AI ────────────────────────────────────
    sql_result = predict_sql_from_fields(fields)
    if sql_result["is_sql"] and sql_result["available"]:
        msg = (f"SQL injection detected by AI model "
               f"(confidence {sql_result['confidence']*100:.1f}%) "
               f"in input: {sql_result['raw_text'][:80]}")
        log_attack(ip, endpoint, "SQL_AI", "SQL_INJECTION", msg, raw_body)
        traffic = _sql_injection_traffic()
        return {
            "blocked":        True,
            "detection":      "SQL_AI",
            "rule":           "SQL_INJECTION",
            "message":        msg,
            "confidence":     sql_result["confidence"],
            "traffic_result": predict_traffic(traffic),
            "sql_result":     sql_result,
            "traffic_data":   traffic,
        }

    # ── Layer 3: Keyword fallback (when SQL model not loaded) ────────
    sql_keywords = ["select", "drop", "insert", "update", "delete",
                    "union", "--", ";", "/*", "*/", "xp_", "exec",
                    "1=1", "or 1", "' or", "\" or"]
    combined = " ".join(str(v) for v in fields.values()).lower()
    if any(kw in combined for kw in sql_keywords):
        msg = f"SQL injection keyword detected in input (keyword rule fallback)"
        log_attack(ip, endpoint, "RULE", "SQL_KEYWORD", msg, raw_body)
        traffic = _sql_injection_traffic()
        return {
            "blocked":        True,
            "detection":      "RULE",
            "rule":           "SQL_KEYWORD",
            "message":        msg,
            "confidence":     0.95,
            "traffic_result": predict_traffic(traffic),
            "sql_result":     sql_result,
            "traffic_data":   traffic,
        }

    # ── All clear ────────────────────────────────────────────────────
    traffic = _normal_traffic()
    return {
        "blocked":        False,
        "detection":      "CLEAN",
        "rule":           "NONE",
        "message":        "All checks passed",
        "confidence":     0.0,
        "traffic_result": predict_traffic(traffic),
        "sql_result":     sql_result,
        "traffic_data":   traffic,
    }


def _build_attack_response(check: dict, attack_type: str) -> dict:
    """Turn a hybrid_check_form result into a JSON-ready response dict."""
    tr = check["traffic_result"]
    return {
        "result":      tr.get("result", "ATTACK"),
        "confidence":  check["confidence"] if check["blocked"]
                       else tr.get("confidence", 0),
        "attack_type": attack_type,
        "blocked":     check["blocked"],
        "detection":   check["detection"],
        "rule":        check["rule"],
        "message":     check["message"],
        "traffic_data": check.get("traffic_data", {}),
        "sql_available": check["sql_result"].get("available", False),
    }


# ════════════════════════════════════════════════════════════════════
#  TRAFFIC FEATURE HELPERS
# ════════════════════════════════════════════════════════════════════

def _normal_traffic():
    return {
        "fwd_packet_length_max": 1460, "fwd_packet_length_mean": 512,
        "subflow_fwd_bytes": 2048,     "packet_length_mean": 400,
        "average_packet_size": 420,    "psh_flag_count": 1,
        "total_length_fwd_packets": 3000, "packet_length_variance": 5000,
        "bwd_packets_per_s": 20,       "flow_duration": 500000,
    }


def _brute_force_traffic(attempt_number=1):
    return {
        "fwd_packet_length_max":    512,
        "fwd_packet_length_mean":   2000,
        "subflow_fwd_bytes":        100,
        "packet_length_mean":       2000,
        "average_packet_size":      2000,
        "psh_flag_count":           1,
        "total_length_fwd_packets": 30000,
        "packet_length_variance":   12,
        "bwd_packets_per_s":        25000,
        "flow_duration":            3,
    }


def _dos_traffic():
    return {
        "fwd_packet_length_max":    0,
        "fwd_packet_length_mean":   0,
        "subflow_fwd_bytes":        0,
        "packet_length_mean":       2,
        "average_packet_size":      3,
        "psh_flag_count":           1,
        "total_length_fwd_packets": 0,
        "packet_length_variance":   12,
        "bwd_packets_per_s":        25000,
        "flow_duration":            3,
    }


def _sql_injection_traffic():
    return {
        "fwd_packet_length_max":    0,
        "fwd_packet_length_mean":   0,
        "subflow_fwd_bytes":        0,
        "packet_length_mean":       2,
        "average_packet_size":      3,
        "psh_flag_count":           1,
        "total_length_fwd_packets": 0,
        "packet_length_variance":   12,
        "bwd_packets_per_s":        25000,
        "flow_duration":            3,
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

    ip       = request.remote_addr
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # ── DoS check on login endpoint itself ───────────────────────────
    dos = check_dos(ip)
    if dos["flagged"]:
        log_attack(ip, "/login", "RULE", "DOS", dos["message"])
        traffic    = _dos_traffic()
        ids_result = predict_traffic(traffic)
        ids_result.update({
            "login_success": False,
            "attempt":       0,
            "blocked":       True,
            "detection":     "RULE",
            "rule":          "DOS",
            "message":       dos["message"],
        })
        return jsonify(ids_result)

    # ── Build & run traffic IDS check ────────────────────────────────
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    login_ok = user and bcrypt.check_password_hash(user["password"], password)

    if login_ok:
        reset_failed_logins(ip)
        session["logged_in"]      = True
        session["username"]       = user["username"]
        session["user_id"]        = user["id"]
        session["balance"]        = user["balance"]
        session["account_number"] = user["account_number"]

        # brute force check (reads existing count before reset)
        bf        = check_brute_force(ip)
        traffic   = _brute_force_traffic(1)
        ids_result = predict_traffic(traffic)
        ids_result.update({
            "login_success": True,
            "attempt":       bf["count"],
            "detection":     "CLEAN",
        })
        return jsonify(ids_result)

    # Failed login — record & check brute force
    record_failed_login(ip)
    bf          = check_brute_force(ip)
    attempt_num = bf["count"]

    if bf["flagged"]:
        log_attack(ip, "/login", "RULE", "BRUTE_FORCE", bf["message"], username)

    traffic    = _brute_force_traffic(attempt_num)
    ids_result = predict_traffic(traffic)
    ids_result.update({
        "result":        "ATTACK" if bf["flagged"] else ids_result.get("result", "NORMAL"),
        "confidence":    1.0 if bf["flagged"] else ids_result.get("confidence", 0.5),
        "login_success": False,
        "attempt":       attempt_num,
        "traffic_data":  traffic,
        "detection":     "RULE" if bf["flagged"] else "TRAFFIC_IDS",
        "rule":          "BRUTE_FORCE" if bf["flagged"] else "NONE",
        "message":       bf.get("message", ""),
        "reason":        "user_not_found" if not user else "wrong_password",
    })
    return jsonify(ids_result)


# ── REGISTER ─────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    ip       = request.remote_addr
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm",  "")

    dos = check_dos(ip)
    if dos["flagged"]:
        return jsonify({"success": False, "error": "Too many requests. Try again later."})

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required."})
    if len(username) < 3:
        return jsonify({"success": False, "error": "Username must be at least 3 characters."})
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."})
    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match."})

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            return jsonify({"success": False, "error": "Username already taken."})

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        acct   = generate_account_number(conn)
        conn.execute(
            "INSERT INTO users (username, password, account_number, balance) VALUES (?,?,?,?)",
            (username, hashed, acct, DEFAULT_BAL)
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
        balance=session.get("balance", DEFAULT_BAL),
        username=session.get("username", "user"),
        account_number=session.get("account_number", "SB-----------"),
    )


# ── SIMULATE DoS ─────────────────────────────────────────────────────
@app.route("/simulate/dos", methods=["POST"])
def simulate_dos():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.remote_addr

    # Fire multiple rapid check_dos calls to trip the threshold
    for _ in range(12):
        check_dos(ip)

    dos_check = check_dos(ip)
    traffic   = _dos_traffic()
    result    = predict_traffic(traffic)
    result.update({
        "result": "ATTACK",
        "confidence": 1.0,
        "attack_type": "DoS Flood",
        "traffic_data": traffic,
        "detection":   "RULE" if dos_check["flagged"] else "TRAFFIC_IDS",
        "rule":        "DOS",
        "message":     dos_check.get("message", "DoS simulation triggered"),
        "blocked":     True,
    })
    if dos_check["flagged"]:
        log_attack(ip, "/simulate/dos", "RULE", "DOS",
                   dos_check["message"])
    return jsonify(result)

# ── TRANSFER  ───────────────────────────────────────────

@app.route("/transfer-page")
def transfer_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template(
        "transfer.html",
        balance=session.get("balance", DEFAULT_BAL),
        account_number=session.get("account_number", "")
    )

# ── (transfer transaction backend) ──────────────────────────────

@app.route("/transfer", methods=["POST"])
def transfer():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.remote_addr
    data = request.json or {}

    amount_raw = str(data.get("amount",    ""))
    recipient  = str(data.get("recipient", ""))
    note       = str(data.get("note",      ""))

    fields = {"recipient": recipient, "amount": amount_raw}
    if note:
        fields["note"] = note

    """sql_keywords   = ["select", "drop", "insert", "update", "delete",
                      "union", "--", ";", "/*", "*/", "xp_", "exec", "1=1", "or 1"]
    combined_input = (amount_raw + recipient + note).lower()
    has_sql        = any(kw in combined_input for kw in sql_keywords)

    if has_sql:
        traffic = _sql_injection_traffic()
        result  = predict_traffic(traffic)
        result["attack_type"]  = "SQL Injection"
        result["blocked"]      = True
        result["traffic_data"] = traffic
        return jsonify(result)"""
# ── Hybrid detection ────────────────────────────────────────────
    check = hybrid_check_form(
        ip=ip,
        endpoint="/transfer",
        fields=fields,
        required=["recipient", "amount"],
        numeric=["amount"],
    )

    if check["blocked"]:
        resp = _build_attack_response(check, check["rule"])
        return jsonify(resp)
    try:
        amount = float(amount_raw)
    except ValueError:
        traffic = _sql_injection_traffic()
        result  = predict_traffic(traffic)
        result["attack_type"]  = "Malformed Input"
        result["blocked"]      = True
        result["traffic_data"] = traffic
        return jsonify(result)

    current_balance = session.get("balance", DEFAULT_BAL)
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
            result  = "ATTACK"
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

# ── AIRTIME PAGE ───────────────────────────────────────────
@app.route("/airtime-page")
def airtime_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template(
        "airtime.html",
        balance=session.get("balance", DEFAULT_BAL),
        account_number=session.get("account_number", ""),
    )


# ── (airtime purchase backend) ──────────────────────────────
@app.route("/airtime", methods=["POST"])
def air_transfer():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    ip   = request.remote_addr
    data = request.json or {}

    amount_raw = str(data.get("amount",    ""))
    recipient  = str(data.get("recipient", ""))
    note       = str(data.get("note",      ""))

    fields = {"recipient": recipient, "amount": amount_raw}
    if note:
        fields["note"] = note

    # ── Hybrid detection ────────────────────────────────────────────
    check = hybrid_check_form(
        ip=ip,
        endpoint="/airtime",
        fields=fields,
        required=["recipient", "amount"],
        numeric=["amount"],
    )

    if check["blocked"]:
        resp = _build_attack_response(check, check["rule"])
        return jsonify(resp)

    # ── Parse amount ─────────────────────────────────────────────────
    try:
        amount = float(amount_raw)
    except ValueError:
        return jsonify({
            "result": "ATTACK", "confidence": 0.9,
            "attack_type": "Malformed Input", "blocked": True,
            "detection": "RULE", "rule": "INVALID_FORM",
            "message": "Amount could not be parsed as a number.",
            "traffic_data": _normal_traffic(),
        })

    current_balance = session.get("balance", DEFAULT_BAL)
    if amount <= 0 or amount > current_balance:
        traffic = _normal_traffic()
        result  = predict_traffic(traffic)
        result.update({
            "attack_type": "Invalid Amount", "blocked": True,
            "detection": "RULE", "rule": "INVALID_FORM",
            "message": "Amount is zero, negative, or exceeds balance.",
            "traffic_data": traffic,
        })
        return jsonify(result)

    # ── Legitimate — resolve recipient ────────────────────────────────
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
            recipient_info = dict(row)

        if recipient_info and recipient_info["account_number"] == session.get("account_number"):
            traffic = _normal_traffic()
            result  = predict_traffic(traffic)
            result.update({
                "attack_type": "Self Transfer", "blocked": True,
                "detection": "RULE", "rule": "INVALID_FORM",
                "message": "Cannot transfer to your own account.",
                "error_msg": "Cannot transfer to your own account.",
                "traffic_data": traffic,
            })
            return jsonify(result)

        new_balance = current_balance - amount
        session["balance"] = new_balance
        conn.execute("UPDATE users SET balance=? WHERE id=?",
                     (new_balance, session["user_id"]))
        if recipient_info:
            conn.execute(
                "UPDATE users SET balance=balance+? WHERE account_number=?",
                (amount, recipient_info["account_number"])
            )
        conn.commit()

    traffic = _normal_traffic()
    result  = predict_traffic(traffic)
    result.update({
        "attack_type":     "Normal Transfer",
        "blocked":         False,
        "detection":       "CLEAN",
        "new_balance":     new_balance,
        "traffic_data":    traffic,
        "recipient_name":  recipient_info["username"] if recipient_info else recipient,
        "recipient_found": recipient_info is not None,
        "sql_available":   sql_model_available(),
    })
    return jsonify(result)


# ── MANUAL IDS CONSOLE ────────────────────────────────────────────────
@app.route("/ids-manual")
def ids_manual():
    return render_template("ids_manual.html")


@app.route("/ids")
def ids_page():
    return redirect(url_for("ids_manual"))


@app.route("/predict", methods=["POST"])
def predict():
    data   = request.json
    result = predict_traffic(data)
    return jsonify(result)


# ── LOGOUT ────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════════
#  STARTUP
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    logger.info(f"SQL injection AI model available: {sql_model_available()}")
    app.run(debug=True)
