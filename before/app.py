"""BEFORE - Vulnerable Notes API (intentionally insecure).

DO NOT deploy this application to production.
"""

import sqlite3

from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)

DB = "users.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, name TEXT, password TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.execute(
        "INSERT INTO users (name, password) VALUES (?, ?)",
        ("admin", "admin123"),
    )
    conn.execute(
        "INSERT INTO users (name, password) VALUES (?, ?)",
        ("alice", "alice123"),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return (
        "<h1>BEFORE - version vulnerable</h1>"
        "<p>Port 5000 - endpoints: "
        "<code>/user?name=</code>, <code>/hello?name=</code></p>"
    )


# VULN 1 - SQL injection (Bandit B608)
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"users": rows, "version": "before"}


# VULN 2 - reflected XSS (Bandit B704)
@app.route("/hello")
def hello():
    name = request.args.get("name", "inconnu")
    return Markup(f"<h1>BEFORE - Bonjour {name}</h1>")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
