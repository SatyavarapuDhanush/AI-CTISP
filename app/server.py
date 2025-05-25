from flask import Flask, request, render_template
from core.honeypot import simulate_honeypot_attack
from core.osint import crawl_osint
from core.gpg_verify import receive_report
from ml.model import validate_threat
from utils.crypto import hash_ioc, MerkleTree
from utils.mitre_mapper import map_to_mitre
import sqlite3, os
from flask import redirect
app = Flask(__name__)
DB_PATH = "database/ioc_logs.db"

def init_db():
    if not os.path.exists("database"):
        os.makedirs("database")
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_hash TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

def insert_to_db(ioc_hash, desc):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs (ioc_hash, description) VALUES (?, ?)", (ioc_hash, desc))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")
@app.route('/submit-form', methods=['POST'])
def submit_form():
    desc = request.form.get("ioc_desc", "").strip().lower()
    report = receive_report()
    hp = simulate_honeypot_attack()
    osint = crawl_osint()


    if any(word in desc for word in ["vpn", "unknown", "suspicious", "brute force"]):
        reporter_trust = 0.9
    elif any(word in desc for word in ["scan", "nmap", "ping"]):
        reporter_trust = 0.6
    else:
        reporter_trust = 0.3

    honeypot_match = 1 if "45.33." in desc or "brute force" in desc else 0

    osint_match = 1 if "leaked" in desc or "sold" in desc else 0

    is_threat, confidence = validate_threat(reporter_trust, honeypot_match, osint_match)

    ioc = desc or hp["source_ip"]
    h = hash_ioc(ioc)
    MerkleTree.store_root([h])

    if is_threat:
        mapped = map_to_mitre(hp)
        insert_to_db(h, f"{desc} (Validated, {confidence}%)")
        return render_template("index.html", result={
            "hash": h,
            "technique": mapped["technique"],
            "description": desc,
            "confidence": confidence
        })
    else:
        insert_to_db(h, f"{desc} (False Positive, {confidence}%)")
        return render_template("index.html", status=f"❌ Threat Not Validated – Confidence: {confidence}%")


def is_admin():
    return True

@app.route('/dashboard')
def dashboard():
    if not is_admin():
        return redirect("/")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT COUNT(*), MAX(timestamp) FROM logs")
    total, _ = cursor.fetchone()
    cursor = conn.execute("SELECT ioc_hash, description FROM logs ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    stats = {
        "total": total,
        "latest_hash": row[0] if row else "N/A",
        "latest_desc": row[1] if row else "N/A"
    }
    return render_template("dashboard.html", stats=stats)

@app.route('/history')
def view_history():
    if not is_admin():
        return redirect("/")
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT ioc_hash, description, timestamp FROM logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template("history.html", records=rows)