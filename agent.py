import os
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

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
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

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
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

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
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

sample_log = """
2026-05-28 03:12:45 FAILED LOGIN user=admin ip=192.168.1.105
2026-05-28 03:12:46 FAILED LOGIN user=admin ip=192.168.1.105
2026-05-28 03:12:47 FAILED LOGIN user=admin ip=192.168.1.105
2026-05-28 03:12:48 FAILED LOGIN user=admin ip=192.168.1.105
2026-05-28 03:12:49 SUCCESS LOGIN user=admin ip=192.168.1.105
"""

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
    
    # Save report to file
    with open("incident_report.txt", "w") as f:
        f.write(report)
    print("\n✅ Report saved to incident_report.txt")