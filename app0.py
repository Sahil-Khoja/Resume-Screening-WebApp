from flask import Flask, render_template, request
import pdfplumber
import ollama
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# ---------------- MongoDB Atlas Connection ----------------
MONGO_URI = "mongodb+srv://bhavyad37_db_user:QnbyhwLb6iClHzHz@cluster0.uclywqb.mongodb.net/?appName=Cluster0"
client = MongoClient(MONGO_URI)

db = client["resume_screening"]
collection = db["results"]

# ---------------- PDF Text Extraction ----------------
def extract_text(pdf_file):
    with pdfplumber.open(pdf_file) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)

# ---------------- LLM Resume Analysis ----------------
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
    response = ollama.generate(
        model="llama3",
        prompt=prompt
    )
    return response["response"]

# ---------------- Routes ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        jd = request.form["jd"]
        resume = request.files["resume"]

        resume_text = extract_text(resume)
        result = analyze_resume(resume_text, jd)

        # ---------- Save to MongoDB ----------
        record = {
            "job_description": jd,
            "resume_filename": resume.filename,
            "resume_text": resume_text,
            "analysis_result": result,
            "created_at": datetime.utcnow()
        }

        collection.insert_one(record)

        return render_template("result.html", result=result)

    return render_template("index.html")

# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(debug=True)
