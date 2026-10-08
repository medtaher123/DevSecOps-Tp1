"""AFTER - Notes API with SAST/SCA fixes applied.

DO NOT deploy this application to production (lab only).
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
        "<h1>AFTER - version corrigee</h1>"
        "<p>Port 5001 - endpoints: "
        "<code>/user?name=</code>, <code>/hello?name=</code></p>"
    )


# FIX 1 - parameterized query
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT id, name FROM users WHERE name = ?",
        (name,),
    ).fetchall()
    conn.close()
    return {"users": rows, "version": "after"}


# FIX 2 - escape untrusted HTML
@app.route("/hello")
def hello():
    name = request.args.get("name", "inconnu")
    return f"<h1>AFTER - Bonjour {escape(name)}</h1>"


if __name__ == "__main__":
    init_db()
    host = os.environ.get("APP_HOST", "0.0.0.0")
    app.run(host=host, port=5000, debug=False)
