"""
CodeAlpha Task 3 - Secure Coding Review
Subject application: "MiniBlog" - REMEDIATED version.
This shows how each finding in the review report is fixed in code.
"""

import os
import sqlite3
from functools import wraps

from flask import Flask, request, redirect, session, abort, escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Fix F-01: secret loaded from environment, never hardcoded / committed
app.secret_key = os.environ.get("MINIBLOG_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("MINIBLOG_SECRET_KEY environment variable must be set")

DB_PATH = "miniblog.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Fix F-02: parameterized query removes SQL injection
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()
        conn.close()

        # Fix F-03: hashed password comparison instead of plaintext
        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["is_admin"] = bool(user[3])
            return redirect("/dashboard")
        return "Invalid login", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # Fix F-03: passwords stored as salted hashes, never plaintext
    password_hash = generate_password_hash(password)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
        (username, password_hash),
    )
    conn.commit()
    conn.close()
    return redirect("/login")


@app.route("/dashboard")
@login_required
def dashboard():
    # Fix F-04: route now requires an authenticated session
    return "Welcome, " + escape(session["username"])


@app.route("/post/<int:post_id>")
def view_post(post_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT title, body, author FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return "Not found", 404

    title, body, author = row
    # Fix F-05: user-supplied fields escaped before insertion into HTML,
    # and no longer passed through render_template_string (removes SSTI risk)
    safe_html = (
        f"<h1>{escape(title)}</h1><p>by {escape(author)}</p><div>{escape(body)}</div>"
    )
    return safe_html


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    # Fix F-02: parameterized LIKE query
    cur.execute("SELECT title FROM posts WHERE title LIKE ?", (f"%{term}%",))
    results = cur.fetchall()
    conn.close()
    return {"results": [r[0] for r in results]}


@app.route("/admin/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    # Fix F-06: destructive action now requires authentication + admin role
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    return "Deleted"


if __name__ == "__main__":
    # Fix F-07: debug mode driven by environment, defaults to OFF
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1")
