from flask import Flask, render_template, request, redirect, session, url_for
import pdfplumber
import ollama
from pymongo import MongoClient
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "mongodb+srv://bhavyad37_db_user:QnbyhwLb6iClHzHz@cluster0.uclywqb.mongodb.net/?appName=Cluster0"

# -------- MongoDB --------
client = MongoClient(
    "mongodb+srv://bhavyad37_db_user:QnbyhwLb6iClHzHz@cluster0.uclywqb.mongodb.net/resume_screening?retryWrites=true&w=majority"
)
db = client["resume_screening"]
users_col = db["users"]
results_col = db["results"]

# -------- Helpers --------
def extract_text(pdf_file):
    with pdfplumber.open(pdf_file) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)

def analyze_resume(resume_text, jd):
    prompt = f"""
You are an ATS resume screening system.

Job Description:
{jd}

Resume:
{resume_text}

Evaluate and return:
1. Match Score (0-100)
2. Skills Match
3. Strengths
4. Weaknesses
5. Final Verdict (Hire / Maybe / Reject)
"""
    return ollama.generate(model="llama3", prompt=prompt)["response"]

# -------- Auth Routes --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        users_col.insert_one({
            "username": request.form["username"],
            "password": generate_password_hash(request.form["password"]),
            "role": "user"
        })
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = users_col.find_one({"username": request.form["username"]})
        if user and check_password_hash(user["password"], request.form["password"]):
            session["user_id"] = str(user["_id"])
            session["role"] = user["role"]
            return redirect("/admin" if user["role"] == "admin" else "/")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------- User Resume Page --------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        jd = request.form["jd"]
        resume = request.files["resume"]

        result = analyze_resume(extract_text(resume), jd)

        results_col.insert_one({
            "user_id": session["user_id"],
            "resume_filename": resume.filename,
            "analysis_result": result,
            "created_at": datetime.utcnow()
        })

        return render_template("result.html", result=result)

    return render_template("index.html")

# -------- Admin Dashboard --------
@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return "Access Denied", 403

    users = list(users_col.find())
    results = list(results_col.find())

    return render_template(
        "admin_dashboard.html",
        users=users,
        results=results
    )

if __name__ == "__main__":
    app.run(debug=True)
