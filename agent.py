import os
import json
import time
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
execution_logs = []

def log_execution(step, input_data, output_data, duration):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "step": step,
        "input_summary": str(input_data)[:200],
        "output_summary": str(output_data)[:200],
        "duration_seconds": round(duration, 2)
    }
    execution_logs.append(entry)
    print(f"[LOG] {entry['timestamp']} | {step} | {duration:.2f}s")

def analyze_logs(log_text):
    prompt = f"""
    You are a cybersecurity analyst. Analyze these logs and find suspicious activity.
    
    LOGS:
    {log_text}
    
    Provide:
    1. Suspicious findings
    2. Severity (HIGH/MEDIUM/LOW)
    3. Evidence (exact log line)
    4. Recommendation
    """
    start = time.time()
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    duration = time.time() - start
    result = response.choices[0].message.content
    log_execution("INITIAL_ANALYSIS", log_text[:100], result[:200], duration)
    return result

def self_correct(log_text, initial_analysis):
    prompt = f"""
    You are a senior cybersecurity analyst reviewing a junior analyst's report.
    
    ORIGINAL LOGS:
    {log_text}
    
    JUNIOR'S ANALYSIS:
    {initial_analysis}
    
    Review the analysis and:
    1. Identify any FALSE POSITIVES
    2. Identify any MISSED threats
    3. Correct any wrong severity ratings
    4. Provide FINAL corrected analysis
    """
    start = time.time()
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    duration = time.time() - start
    result = response.choices[0].message.content
    log_execution("SELF_CORRECTION", initial_analysis[:100], result[:200], duration)
    return result

def generate_report(log_text, initial_analysis, corrected_analysis):
    prompt = f"""
    Create a professional incident response report.
    
    LOGS: {log_text}
    INITIAL ANALYSIS: {initial_analysis}
    CORRECTED ANALYSIS: {corrected_analysis}
    
    Format the report as:
    
    INCIDENT REPORT
    ===============
    Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}
    
    EXECUTIVE SUMMARY:
    [2-3 sentences]
    
    FINDINGS:
    [List confirmed threats with evidence]
    
    FALSE POSITIVES IDENTIFIED:
    [What was incorrectly flagged]
    
    SEVERITY: [FINAL severity]
    
    RECOMMENDATIONS:
    [Action items]
    
    CONCLUSION:
    [Final statement]
    """
    start = time.time()
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    duration = time.time() - start
    result = response.choices[0].message.content
    log_execution("REPORT_GENERATION", corrected_analysis[:100], result[:200], duration)
    return result

# Read real Apache log file
with open("Apache/Apache.log", "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()[:100]
    sample_log = "".join(lines)

if __name__ == "__main__":
    print("=" * 50)
    print("STEP 1: Initial Analysis...")
    print("=" * 50)
    initial = analyze_logs(sample_log)
    print(initial)

    print("\n" + "=" * 50)
    print("STEP 2: Self-Correction...")
    print("=" * 50)
    corrected = self_correct(sample_log, initial)
    print(corrected)

    print("\n" + "=" * 50)
    print("STEP 3: Final Report...")
    print("=" * 50)
    report = generate_report(sample_log, initial, corrected)
    print(report)

    # Save report
    with open("incident_report.txt", "w") as f:
        f.write(report)
    print("\n✅ Report saved to incident_report.txt")

    # Save execution logs
    with open("execution_logs.json", "w") as f:
        json.dump(execution_logs, f, indent=2)
    print("✅ Execution logs saved to execution_logs.json")