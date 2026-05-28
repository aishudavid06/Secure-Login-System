from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime

app = Flask(__name__)

app.secret_key = "super_secure_secret_key"

bcrypt = Bcrypt(app)

# DATABASE CONNECTION
def connect_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# CREATE TABLE
conn = connect_db()

conn.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT
)
""")

conn.commit()
conn.close()

# HOME PAGE
@app.route("/")
def home():
    return render_template("home.html")

# ABOUT PAGE
@app.route("/about")
def about():
    return render_template("about.html")

# REGISTER PAGE
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # INPUT VALIDATION
        if len(password) < 8:
            flash("Password must contain at least 8 characters")
            return redirect("/register")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        try:

            conn = connect_db()

            conn.execute(
                "INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)",
                (
                    username,
                    email,
                    hashed_password,
                    datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                )
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect("/login")

        except:
            flash("Email already exists")
            return redirect("/register")

    return render_template("register.html")

# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = connect_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        conn.close()

        if user and bcrypt.check_password_hash(user["password"], password):

            session["user"] = user["username"]
            session["email"] = user["email"]
            session["created_at"] = user["created_at"]

            flash("Secure Authentication Successful")

            return redirect("/dashboard")

        else:
            flash("Invalid Email or Password")

    return render_template("login.html")

# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["user"],
        email=session["email"],
        created_at=session["created_at"]
    )

# PROFILE PAGE
@app.route("/profile")
def profile():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "profile.html",
        username=session["user"],
        email=session["email"],
        created_at=session["created_at"]
    )

# SECURITY PAGE
@app.route("/security")
def security():

    if "user" not in session:
        return redirect("/login")

    return render_template("security.html")

# LOGOUT
@app.route("/logout")
def logout():

    session.clear()

    flash("Logged Out Successfully")

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)