from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
import pdfplumber
from pymongo import MongoClient
from datetime import datetime, timezone
import os
from groq import Groq
from flask_bcrypt import Bcrypt
import io
import re
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "devsecretkey"
bcrypt = Bcrypt(app)

# ---------------- ENV VARIABLES ----------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
if not GROQ_API_KEY or not MONGO_URI:
    raise ValueError("GROQ_API_KEY or MONGO_URI not set in .env")

# ---------------- GROQ CLIENT ----------------
client = Groq(api_key=GROQ_API_KEY)

# ---------------- MongoDB ----------------
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["resume_screening"]
users_col = db["users"]
results_col = db["results"]
vault_col = db["vault_resumes"]  # Resume Vault collection

# ---------------- PDF TEXT EXTRACTION ----------------
def extract_text(pdf_file):
    with pdfplumber.open(pdf_file) as pdf:
        text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    return text.strip() or "[No text extracted]"

def extract_text_from_bytes(file_bytes):
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    return text.strip() or "[No text extracted]"

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
  Python: <0-100>
  SQL: <0-100>
  Java: <0-100>
  JavaScript: <0-100>
  Hibernate: <0-100>
  HTML/CSS/JS: <0-100>
Strengths:
Weaknesses:
Final Verdict: Hire / Maybe / Reject
Reason: <Explain why>
"""
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    return response.choices[0].message.content

# ---------------- RESULT PARSER ----------------
def parse_result_text(result_text):
    # Match Score
    match = re.search(r"Match Score:\s*(\d+)", result_text)
    match_score = int(match.group(1)) if match else 0

    # Skills Match
    skills_match = {}
    skills_section = re.search(r"Skills Match:\s*([\s\S]*?)\n(?:Strengths|Weaknesses|Final Verdict)", result_text)
    if skills_section:
        for line in skills_section.group(1).split("\n"):
            parts = line.split(":")
            if len(parts) == 2:
                skills_match[parts[0].strip()] = int(parts[1].strip())

    # Strengths
    strengths = []
    strengths_section = re.search(r"Strengths:\s*([\s\S]*?)\n(?:Weaknesses|Final Verdict|Reason)", result_text)
    if strengths_section:
        strengths = [line.strip(" -") for line in strengths_section.group(1).split("\n") if line.strip()]

    # Weaknesses
    weaknesses = []
    weaknesses_section = re.search(r"Weaknesses:\s*([\s\S]*?)\n(?:Final Verdict|Reason|$)", result_text)
    if weaknesses_section:
        weaknesses = [line.strip(" -") for line in weaknesses_section.group(1).split("\n") if line.strip()]

    # Final Verdict
    verdict_match = re.search(r"Final Verdict:\s*(\w+)", result_text)
    final_verdict = verdict_match.group(1) if verdict_match else "Unknown"

    # Reason
    reason_match = re.search(r"Reason:\s*(.*)", result_text)
    reason = reason_match.group(1) if reason_match else "Reason not provided."

    return {
        "match_score": match_score,
        "skills_match": skills_match,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "final_verdict": final_verdict,
        "reason": reason
    }

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    vault_resumes = list(vault_col.find({"user": session["user"]}, {"filename": 1, "_id": 0}))

    if request.method == "POST":
        jd = request.form.get("jd")
        resume_file = request.files.get("resume")
        selected_vault_resume = request.form.get("vault_resume_select")

        if selected_vault_resume:
            doc = vault_col.find_one({"user": session["user"], "filename": selected_vault_resume})
            if not doc:
                flash("Selected resume not found in your vault.", "danger")
                return redirect(url_for("index"))
            resume_text = extract_text_from_bytes(doc["file_data"])
            resume_filename = doc["filename"]
        elif resume_file:
            if not resume_file.filename.lower().endswith(".pdf"):
                flash("Only PDF files allowed.", "danger")
                return redirect(url_for("index"))
            resume_text = extract_text(resume_file)
            resume_filename = resume_file.filename
        else:
            flash("Please upload or select a resume.", "danger")
            return redirect(url_for("index"))

        if not jd:
            flash("Please provide a Job Description.", "danger")
            return redirect(url_for("index"))

        # Analyze resume
        result = analyze_resume(resume_text, jd)
        result_data = parse_result_text(result)

        # Save in DB
        results_col.insert_one({
            "user": session["user"],
            "job_description": jd,
            "resume_filename": resume_filename,
            "analysis_result": result,
            "created_at": datetime.now(timezone.utc)
        })

        flash("Resume analyzed successfully!", "success")
        return render_template(
            "result.html",
            result=result,
            result_data=result_data,
            resume_filename=resume_filename,   # <--- add this
            candidate_name=session.get("user", "Candidate")
        )


    return render_template("index.html", vault_resumes=vault_resumes)

@app.route("/upload_resume", methods=["POST"])
def upload_resume():
    if "user" not in session:
        flash("Login required.", "danger")
        return redirect(url_for("login"))

    resume = request.files.get("vault_resume")
    if not resume or not resume.filename.lower().endswith(".pdf"):
        flash("Please upload a valid PDF file.", "danger")
        return redirect(url_for("index"))

    vault_col.insert_one({
        "user": session["user"],
        "filename": resume.filename,
        "file_data": resume.read(),
        "uploaded_at": datetime.now(timezone.utc)
    })
    flash(f"Resume '{resume.filename}' saved to Vault!", "success")
    return redirect(url_for("index"))

# ---------------- REGISTER / LOGIN / LOGOUT ----------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for("register"))
        if users_col.find_one({"username": username}):
            flash("Username exists!", "danger")
            return redirect(url_for("register"))
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        users_col.insert_one({"username": username, "password": hashed_pw})
        session["user"] = username
        flash(f"Welcome, {username}!", "success")
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Username/password required", "danger")
            return redirect(url_for("login"))
        user = users_col.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out.", "success")
    return redirect(url_for("login"))

# ---------------- ADMIN ----------------
@app.route("/admin")
def admin():
    if "user" not in session or session["user"] != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("login"))
    all_results = list(results_col.find().sort("created_at",-1))
    return render_template("admin.html", results=all_results)

from flask import send_file
from fpdf import FPDF  # pip install fpdf

@app.route("/download_report/<resume_filename>", methods=["GET"])
def download_report(resume_filename):
    if "user" not in session:
        flash("Login required.", "danger")
        return redirect(url_for("login"))

    # Find latest result for this resume for this user
    result_doc = results_col.find_one(
        {"user": session["user"], "resume_filename": resume_filename},
        sort=[("created_at", -1)]
    )

    if not result_doc:
        flash("Report not found.", "danger")
        return redirect(url_for("index"))

    # Parse result
    result_data = parse_result_text(result_doc["analysis_result"])
    candidate_name = result_doc["user"]

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Resume Analysis Report - {candidate_name}", ln=True, align="C")
    pdf.ln(5)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Resume File: {resume_filename}", ln=True)
    pdf.cell(0, 10, f"Match Score: {result_data['match_score']}%", ln=True)
    pdf.ln(3)

    pdf.cell(0, 10, "Skills Match:", ln=True)
    for skill, score in result_data['skills_match'].items():
        pdf.cell(0, 10, f" - {skill}: {score}%", ln=True)

    pdf.ln(3)
    pdf.cell(0, 10, "Strengths:", ln=True)
    for s in result_data['strengths']:
        pdf.cell(0, 10, f" - {s}", ln=True)

    pdf.ln(3)
    pdf.cell(0, 10, "Weaknesses:", ln=True)
    for w in result_data['weaknesses']:
        pdf.cell(0, 10, f" - {w}", ln=True)

    pdf.ln(3)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Final Verdict: {result_data['final_verdict']}", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, f"Reason: {result_data['reason']}")

    # Save to BytesIO

    # Get PDF as bytes
    pdf_bytes = pdf.output(dest='S').encode('latin1')  # dest='S' returns string, encode to bytes

    # Write to BytesIO
    pdf_output = io.BytesIO(pdf_bytes)
    pdf_output.seek(0)


    return send_file(pdf_output, download_name=f"{resume_filename}_report.pdf", as_attachment=True, mimetype='application/pdf')




# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
