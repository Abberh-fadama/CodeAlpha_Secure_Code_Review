"""
CodeAlpha Task 3 - Secure Coding Review
Subject application: "MiniBlog" - a small Flask blog/login app.
This file is the ORIGINAL (pre-review) version, intentionally written the
way a rushed junior developer might write it, so it contains realistic
vulnerabilities for the review to find. It is used only as a review
subject inside this internship submission - it is not deployed anywhere.
"""

import sqlite3
from flask import Flask, request, redirect, session, render_template_string

app = Flask(__name__)
app.secret_key = "supersecret123"  # hardcoded secret key

DB_PATH = "miniblog.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Vulnerability: SQL built with string formatting -> SQL injection
        query = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            password,
        )
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query)
        user = cur.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect("/dashboard")
        else:
            return "Invalid login"

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
    password = request.form["password"]  # stored as plain text

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    )
    conn.commit()
    conn.close()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    # Vulnerability: no check that session["user_id"] exists -> broken access control
    username = session.get("username", "Guest")
    return "Welcome, " + username


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
    # Vulnerability: body rendered as raw HTML/Jinja from user-submitted content -> stored XSS / SSTI
    template = """
        <h1>{title}</h1>
        <p>by {author}</p>
        <div>""" + body + """</div>
    """.format(title=title, author=author)
    return render_template_string(template)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    # Vulnerability: SQL injection via search parameter
    cur.execute("SELECT title FROM posts WHERE title LIKE '%" + term + "%'")
    results = cur.fetchall()
    conn.close()
    return {"results": [r[0] for r in results]}


@app.route("/admin/delete/<int:post_id>")
def delete_post(post_id):
    # Vulnerability: no authentication/authorization check at all on a destructive action
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    return "Deleted"


if __name__ == "__main__":
    # Vulnerability: debug mode exposes Werkzeug interactive debugger/RCE in production
    app.run(debug=True, host="0.0.0.0")
