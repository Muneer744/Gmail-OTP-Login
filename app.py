from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

import os
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "change-this-secret-key"
)


# =========================================================
# DATABASE
# =========================================================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========================================================
# USER DATABASE MODEL
# =========================================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    verified = db.Column(
        db.Boolean,
        default=False
    )


# =========================================================
# GMAIL SETTINGS
# =========================================================

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")


# =========================================================
# SEND OTP FUNCTION
# =========================================================

def send_otp_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = "Your Verification OTP"
    message["From"] = GMAIL_USER
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your verification OTP is:

{otp}

This OTP is valid for 5 minutes.

If you did not request this code, please ignore this email.

Thank you.
"""
    )

    with smtplib.SMTP(
        "smtp.gmail.com",
        587
    ) as server:

        server.starttls()

        server.login(
            GMAIL_USER,
            GMAIL_APP_PASSWORD
        )

        server.send_message(message)


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route("/")
def login():

    return render_template("login.html")


# =========================================================
# SIGN UP PAGE
# =========================================================

@app.route("/register")
def register():

    return render_template("register.html")


# =========================================================
# CREATE ACCOUNT
# =========================================================

@app.route("/register", methods=["POST"])
def create_account():

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )


    # Check name

    if not name:

        flash("Please enter your name.")

        return redirect(
            url_for("register")
        )


    # Check Gmail

    if not email.endswith("@gmail.com"):

        flash("Please enter a valid Gmail address.")

        return redirect(
            url_for("register")
        )


    # Check password

    if len(password) < 6:

        flash(
            "Password must contain at least 6 characters."
        )

        return redirect(
            url_for("register")
        )


    # Check password confirmation

    if password != confirm_password:

        flash("Passwords do not match.")

        return redirect(
            url_for("register")
        )


    # Check existing user

    existing_user = User.query.filter_by(
        email=email
    ).first()


    if existing_user:

        flash(
            "An account with this Gmail already exists. Please sign in."
        )

        return redirect(
            url_for("login")
        )


    # Generate OTP

    otp = str(
        random.randint(
            100000,
            999999
        )
    )


    # Store registration information temporarily

    session["register_name"] = name
    session["register_email"] = email
    session["register_password"] = password

    session["otp"] = otp

    session["otp_expiry"] = (
        datetime.now()
        + timedelta(minutes=5)
    ).timestamp()

    session["otp_purpose"] = "register"


    # Send OTP

    try:

        send_otp_email(
            email,
            otp
        )

        flash(
            "Verification OTP has been sent to your Gmail."
        )

        return redirect(
            url_for("verify")
        )

    except Exception as error:

        print(
            "Email error:",
            error
        )

        flash(
            "Unable to send OTP. Please check Gmail configuration."
        )

        return redirect(
            url_for("register")
        )


# =========================================================
# SIGN IN
# =========================================================

@app.route("/login", methods=["POST"])
def sign_in():

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )


    # Find user

    user = User.query.filter_by(
        email=email
    ).first()


    if not user:

        flash(
            "Account not found. Please create an account first."
        )

        return redirect(
            url_for("login")
        )


    # Check password

    if not check_password_hash(
        user.password,
        password
    ):

        flash(
            "Incorrect email or password."
        )

        return redirect(
            url_for("login")
        )


    # Generate login OTP

    otp = str(
        random.randint(
            100000,
            999999
        )
    )


    session["login_user_id"] = user.id
    session["login_email"] = user.email

    session["otp"] = otp

    session["otp_expiry"] = (
        datetime.now()
        + timedelta(minutes=5)
    ).timestamp()

    session["otp_purpose"] = "login"


    # Send OTP

    try:

        send_otp_email(
            user.email,
            otp
        )

        flash(
            "Login OTP has been sent to your Gmail."
        )

        return redirect(
            url_for("verify")
        )

    except Exception as error:

        print(
            "Email error:",
            error
        )

        flash(
            "Unable to send OTP. Please try again."
        )

        return redirect(
            url_for("login")
        )


# =========================================================
# VERIFY OTP PAGE
# =========================================================

@app.route("/verify")
def verify():

    if "otp" not in session:

        return redirect(
            url_for("login")
        )


    email = (
        session.get("login_email")
        or
        session.get("register_email")
    )


    return render_template(
        "verify.html",
        email=email
    )


# =========================================================
# VERIFY OTP
# =========================================================

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    entered_otp = request.form.get(
        "otp",
        ""
    ).strip()

    saved_otp = session.get(
        "otp"
    )

    expiry = session.get(
        "otp_expiry"
    )

    purpose = session.get(
        "otp_purpose"
    )


    # Check OTP

    if not saved_otp or not expiry:

        flash(
            "OTP expired. Please try again."
        )

        return redirect(
            url_for("login")
        )


    # Check expiry

    if datetime.now().timestamp() > expiry:

        session.pop(
            "otp",
            None
        )

        session.pop(
            "otp_expiry",
            None
        )

        flash(
            "OTP expired. Please request a new OTP."
        )

        return redirect(
            url_for("login")
        )


    # Check OTP value

    if entered_otp != saved_otp:

        flash(
            "Incorrect OTP. Please try again."
        )

        return redirect(
            url_for("verify")
        )


    # =====================================================
    # REGISTRATION OTP
    # =====================================================

    if purpose == "register":

        name = session.get(
            "register_name"
        )

        email = session.get(
            "register_email"
        )

        password = session.get(
            "register_password"
        )


        # Hash password

        hashed_password = generate_password_hash(
            password
        )


        # Create user

        new_user = User(

            name=name,

            email=email,

            password=hashed_password,

            verified=True
        )


        db.session.add(
            new_user
        )

        db.session.commit()


        # Login user

        session.clear()

        session["logged_in"] = True

        session["user_id"] = new_user.id

        session["user_email"] = new_user.email

        session["user_name"] = new_user.name


        return redirect(
            url_for("dashboard")
        )


    # =====================================================
    # LOGIN OTP
    # =====================================================

    if purpose == "login":

        user_id = session.get(
            "login_user_id"
        )

        user = db.session.get(
            User,
            user_id
        )


        if not user:

            session.clear()

            flash(
                "User account not found."
            )

            return redirect(
                url_for("login")
            )


        session.clear()

        session["logged_in"] = True

        session["user_id"] = user.id

        session["user_email"] = user.email

        session["user_name"] = user.name


        return redirect(
            url_for("dashboard")
        )


    flash(
        "Invalid verification request."
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            url_for("login")
        )


    return render_template(
        "dashboard.html",

        name=session.get(
            "user_name"
        ),

        email=session.get(
            "user_email"
        )
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# CREATE DATABASE
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True
    )