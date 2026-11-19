
import os
import io
import base64
import sqlite3

import pyotp
import qrcode

from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", os.urandom(32)
)

DB = "users.db"


def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                mfa_enabled INTEGER DEFAULT 0
            )
        """)

        user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("student",)
        ).fetchone()

        if not user:
            db.execute("""
                INSERT INTO users
                (username, password_hash)
                VALUES (?, ?)
            """, (
                "student",
                generate_password_hash("DemoPass123!")
            ))


def get_user():
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE username = ?",
            ("student",)
        ).fetchone()


def check_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = get_user()

    if (user and username == user["username"]
            and check_password_hash(
                user["password_hash"], password
            )):
        return user

    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login-basic", methods=["GET", "POST"])
def login_basic():
    error = None

    if request.method == "POST":
        user = check_login()

        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["auth_method"] = "basic"
            return redirect(url_for("dashboard"))

        error = "Incorrect username or password."

    return render_template(
        "login_basic.html", error=error
    )


@app.route("/login-mfa", methods=["GET", "POST"])
def login_mfa():
    error = None

    if request.method == "POST":
        user = check_login()

        if user:
            session.clear()
            session["pending_user"] = user["id"]

            if not user["mfa_enabled"]:
                return redirect(url_for("setup_mfa"))

            return redirect(url_for("verify_mfa"))

        error = "Incorrect username or password."

    return render_template(
        "login_mfa.html", error=error
    )


@app.route("/setup-mfa", methods=["GET", "POST"])
def setup_mfa():
    user = get_user()

    if session.get("pending_user") != user["id"]:
        return redirect(url_for("login_mfa"))

    if user["mfa_enabled"]:
        return redirect(url_for("verify_mfa"))

    if "setup_secret" not in session:
        session["setup_secret"] = pyotp.random_base32()

    secret = session["setup_secret"]
    error = None

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if pyotp.TOTP(secret).verify(
            code, valid_window=1
        ):
            with get_db() as db:
                db.execute("""
                    UPDATE users
                    SET totp_secret = ?,
                        mfa_enabled = 1
                    WHERE id = ?
                """, (secret, user["id"]))

            session.pop("setup_secret", None)
            session.pop("pending_user", None)
            session["user_id"] = user["id"]
            session["auth_method"] = "mfa"
            return redirect(url_for("dashboard"))

        error = "Invalid setup code. Try again."

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["username"],
        issuer_name="Student MFA Project"
    )

    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    qr_code = base64.b64encode(
        buffer.getvalue()
    ).decode()

    return render_template(
        "setup_mfa.html",
        qr_code=qr_code,
        error=error
    )


@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    user = get_user()

    if session.get("pending_user") != user["id"]:
        return redirect(url_for("login_mfa"))

    if not user["mfa_enabled"]:
        return redirect(url_for("setup_mfa"))

    error = None

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):
            session.pop("pending_user", None)
            session["user_id"] = user["id"]
            session["auth_method"] = "mfa"
            return redirect(url_for("dashboard"))

        error = "Invalid or expired MFA code."

    return render_template(
        "verify_mfa.html", error=error
    )


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        auth_method=session["auth_method"]
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
app.run(
    host="127.0.0.1",
    port=5000,
    debug=False
)