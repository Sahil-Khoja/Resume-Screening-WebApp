from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
import pdfplumber
from pymongo import MongoClient
from datetime import datetime, timezone
import os
from groq import Groq
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

# ---------------- ENV VARIABLES ----------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# ---------------- GROQ CLIENT ----------------
client = Groq(api_key=GROQ_API_KEY)

# ---------------- MongoDB ----------------
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["resume_screening"]
users_col = db["users"]
results_col = db["results"]

# ---------------- PDF TEXT EXTRACTION ----------------
def extract_text(pdf_file):
    with pdfplumber.open(pdf_file) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)

# ---------------- RESUME ANALYSIS ----------------
def analyze_resume(resume_text, jd):
    prompt = f"""
You are an ATS resume screening system.

Job Description:
{jd}

Resume:
{resume_text}

Return result strictly in this format:

Match Score: <0-100>
Skills Match:
Strengths:
Weaknesses:
Final Verdict: Hire / Maybe / Reject
"""
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    return response.choices[0].message.content

# ---------------- ROUTES ----------------

# Home Page
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        jd = request.form["jd"]
        resume = request.files["resume"]

        resume_text = extract_text(resume)
        result = analyze_resume(resume_text, jd)

        record = {
            "user": session["user"],
            "job_description": jd,
            "resume_filename": resume.filename,
            "analysis_result": result,
            "created_at": datetime.now(timezone.utc)
        }

        results_col.insert_one(record)
        flash("Resume analyzed successfully!", "success")

        return render_template("result.html", result=result)

    return render_template("index.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if users_col.find_one({"username": username}):
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        users_col.insert_one({"username": username, "password": hashed_pw})
        flash("Registered successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = users_col.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
def admin():
    if "user" not in session or session["user"] != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))

    all_results = list(results_col.find().sort("created_at", -1))
    return render_template("admin.html", results=all_results)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
