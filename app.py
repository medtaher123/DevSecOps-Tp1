"""Vulnerable Notes API — intentionally insecure for a DevSecOps lab.

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
        "Vulnerable Notes API — endpoints: "
        "/user?name=… , /hello?name=…"
    )


# VULN 1 — SQL injection (Bandit B608): user input is concatenated into SQL.
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"users": rows}


# VULN 2 — reflected XSS (Bandit B704): Markup marks untrusted input as safe HTML.
@app.route("/hello")
def hello():
    name = request.args.get("name", "inconnu")
    return Markup(f"<h1>Bonjour {name}</h1>")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
