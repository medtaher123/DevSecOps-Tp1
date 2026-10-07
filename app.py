"""Vulnerable Notes API - intentionally insecure for a DevSecOps lab.

DO NOT deploy this application to production.
"""

import os
import sqlite3

from flask import Flask, request
from markupsafe import escape

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
        "Vulnerable Notes API - endpoints: "
        "/user?name=… , /hello?name=…"
    )


# FIX 1 - parameterized query (no string concatenation)
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT id, name FROM users WHERE name = ?",
        (name,),
    ).fetchall()
    conn.close()
    return {"users": rows}


# FIX 2 - escape untrusted input before returning HTML
@app.route("/hello")
def hello():
    name = request.args.get("name", "inconnu")
    return f"<h1>Bonjour {escape(name)}</h1>"


if __name__ == "__main__":
    init_db()
    # Bind address from env so Docker can set 0.0.0.0 without hardcoding it here
    # (avoids Bandit B104 in application code).
    host = os.environ.get("APP_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=False)
