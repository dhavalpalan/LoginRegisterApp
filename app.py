"""Simple Login and Registration System - Flask + SQLite.

Security features: password hashing, parameterized SQL, CSRF protection,
password-strength validation, login-attempt lockout, session timeout.
"""
import os
import re
import sqlite3
from datetime import datetime, timedelta

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(24)),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # session timeout
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
csrf = CSRFProtect(app)

DATABASE = "users.db"
MAX_ATTEMPTS = 5
LOCK_MINUTES = 5
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   email TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   failed_attempts INTEGER NOT NULL DEFAULT 0,
                   locked_until TEXT,
                   created_at TEXT NOT NULL
               )"""
        )


# ---------- validation ----------
def password_problems(pw):
    problems = []
    if len(pw) < 8:
        problems.append("at least 8 characters")
    if not re.search(r"[A-Z]", pw):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", pw):
        problems.append("a lowercase letter")
    if not re.search(r"\d", pw):
        problems.append("a digit")
    if not re.search(r"[^\w\s]", pw):
        problems.append("a special character")
    return problems


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            errors.append("Username must be 3-20 letters, digits or underscores.")
        if not EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")
        missing = password_problems(password)
        if missing:
            errors.append("Password needs " + ", ".join(missing) + ".")

        if not errors:
            db = get_db()
            dup = db.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if dup:
                errors.append("Username or email already registered.")
            else:
                db.execute(
                    "INSERT INTO users (username, email, password_hash, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password),
                     datetime.now().isoformat(timespec="seconds")),
                )
                db.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))

        for e in errors:
            flash(e, "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE lower(username) = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        if user and user["locked_until"]:
            until = datetime.fromisoformat(user["locked_until"])
            if until > datetime.now():
                mins = int((until - datetime.now()).total_seconds() // 60) + 1
                flash(f"Account locked. Try again in {mins} minute(s).", "danger")
                return render_template("login.html")

        if user and check_password_hash(user["password_hash"], password):
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        if user:
            attempts = user["failed_attempts"] + 1
            locked = None
            if attempts >= MAX_ATTEMPTS:
                locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                attempts = 0
                flash(f"Too many failed attempts. Locked for {LOCK_MINUTES} minutes.", "danger")
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked, user["id"]),
            )
            db.commit()
        # same message either way: do not reveal which accounts exist
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT username, email, created_at FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    return render_template("dashboard.html", user=user)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

        errors = []
        if not check_password_hash(user["password_hash"], current):
            errors.append("Current password is incorrect.")
        if new != confirm:
            errors.append("New passwords do not match.")
        missing = password_problems(new)
        if missing:
            errors.append("New password needs " + ", ".join(missing) + ".")

        if not errors:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(new), user["id"]))
            db.commit()
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
        for e in errors:
            flash(e, "danger")
    return render_template("change_password.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    return resp


init_db()

if __name__ == "__main__":
    app.run(debug=True)
