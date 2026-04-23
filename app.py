from flask import Flask, render_template, request, redirect, session
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
import sqlite3, os, random

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# =========================
# LOGIN DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper


# =========================
# EMAIL CONFIG
# =========================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL")
app.config['MAIL_PASSWORD'] = os.getenv("PASSWORD")

mail = Mail(app)

# =========================
# DB
# =========================
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        first_login INTEGER DEFAULT 1
    )
    """)

    conn.commit()
    conn.close()

init_db()

# =========================
# DEFAULT USER (FIXED ✅)
# =========================
def create_default_user():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # 🔥 لا تحذف المستخدم
    c.execute("SELECT * FROM users WHERE username='admin'")
    user = c.fetchone()

    if not user:
        c.execute("""
        INSERT INTO users (username, password, email, first_login)
        VALUES (?, ?, ?, ?)
        """, (
            "admin",
            generate_password_hash("1234"),
            "admin@test.com",
            1
        ))

    conn.commit()
    conn.close()

create_default_user()

# =========================
# LOGIN
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=? OR email=?", (username, username))
        user = c.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]

            if user[4] == 1:
                return redirect("/change")

            return redirect("/dashboard")

        return "❌ error"

    return render_template("login.html")


# =========================
# CHANGE EMAIL / PASSWORD
# =========================
@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":

        email = request.form["email"]
        old_pass = request.form["old_pass"]
        new_pass = request.form["new_pass"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id=?", (session["user_id"],))
        data = c.fetchone()
        conn.close()

        if not data:
            return "❌ user not found"

        if not check_password_hash(data[0], old_pass):
            return "❌ wrong password"

        session.pop("code", None)
        session.pop("action", None)

        code = str(random.randint(100000, 999999))

        session["code"] = code
        session["email"] = email
        session["new_pass"] = generate_password_hash(new_pass)
        session["action"] = "email_change"

        msg = Message(
            subject="Verification Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Code: {code}"
        mail.send(msg)

        return redirect("/verify")

    return render_template("change.html")


# =========================
# VERIFY EMAIL CHANGE
# =========================
@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    if session.get("action") != "email_change":
        return redirect("/dashboard")

    if request.method == "POST":
        code = request.form["code"]

        if code == session.get("code"):

            conn = sqlite3.connect("database.db")
            c = conn.cursor()

            c.execute("""
            UPDATE users 
            SET email=?, password=?, first_login=0 
            WHERE id=?
            """, (
                session["email"],
                session["new_pass"],
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            session.clear()

            return redirect("/")

        return "❌ wrong code"

    return render_template("verify.html")


# =========================
# FORGOT PASSWORD
# =========================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            return "❌ email not found"

        code = str(random.randint(100000, 999999))

        session["reset_code"] = code
        session["reset_email"] = email

        msg = Message(
            subject="Reset Password Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Your reset code is: {code}"
        mail.send(msg)

        return redirect("/reset")

    return render_template("forgot.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        code = request.form["code"]
        new_pass = request.form["new_pass"]

        if code != session.get("reset_code"):
            return "❌ wrong code"

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        c.execute("""
        UPDATE users 
        SET password=? 
        WHERE email=?
        """, (
            generate_password_hash(new_pass),
            session["reset_email"]
        ))

        conn.commit()
        conn.close()

        session.pop("reset_code", None)
        session.pop("reset_email", None)

        return redirect("/")

    return render_template("reset.html")


# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =========================
# CHANGE PASSWORD
# =========================
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_pass = request.form["old_pass"]
        new_pass = request.form["new_pass"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT password, email FROM users WHERE id=?", (session["user_id"],))
        data = c.fetchone()
        conn.close()

        if not data:
            return "❌ user not found"

        if not check_password_hash(data[0], old_pass):
            return "❌ wrong password"

        session.pop("code", None)
        session.pop("action", None)

        code = str(random.randint(100000, 999999))

        session["code"] = code
        session["new_pass"] = generate_password_hash(new_pass)
        session["action"] = "password_change"

        msg = Message(
            subject="Password Change Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[data[1]]
        )
        msg.body = f"Your code is: {code}"
        mail.send(msg)

        return redirect("/verify-password")

    return render_template("change_password.html")


@app.route("/verify-password", methods=["GET", "POST"])
@login_required
def verify_password():
    if session.get("action") != "password_change":
        return redirect("/dashboard")

    if request.method == "POST":
        code = request.form["code"]

        if code == session.get("code"):

            conn = sqlite3.connect("database.db")
            c = conn.cursor()

            c.execute("""
            UPDATE users SET password=? WHERE id=?
            """, (
                session["new_pass"],
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            session.clear()

            return redirect("/")

        return "❌ wrong code"

    return render_template("verify_password.html")


# =========================
# RUN
# =========================
app.run(host="0.0.0.0", port=3000, debug=True)