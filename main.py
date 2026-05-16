# ============================================================
# main.py — LLM Security Gateway (Final)
# FastAPI backend with hybrid detection and audit logging
# ============================================================

import os
import time
import uuid
import json
from datetime import datetime

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from injection import detect_injection
from semantic_detector import detect_semantic
from presidio_engine import analyze_pii
from policy_engine import make_decision
from language_detector import detect_language
from config import AUDIT_LOG_PATH, POLICY_SETTINGS

# ── App Setup ─────────────────────────────────────────────
app = FastAPI(
    title="LLM Security Gateway — Final",
    description="Robust multilingual security gateway for LLM applications",
    version="2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)
os.makedirs("models", exist_ok=True)

# ── Audit Logger ──────────────────────────────────────────
def write_audit_log(record: dict):
    """Appends one JSON record per line to the audit log file."""
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

# ── Root Page ─────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <html>
    <head>
        <title>LLM Security Gateway</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: #f5f5f5;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .card {
                background: white;
                border-radius: 16px;
                padding: 48px;
                box-shadow: 0 4px 24px rgba(0,0,0,0.08);
                text-align: center;
                max-width: 480px;
            }
            h2 { color: #6c63ff; margin-bottom: 8px; }
            p  { color: #555; }
            a  {
                display: inline-block;
                margin: 8px;
                padding: 10px 24px;
                background: #6c63ff;
                color: white;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 500;
            }
            a:hover { background: #574fd6; }
            .status { color: #22c55e; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>⬡ LLM Security Gateway</h2>
            <p class="status">● Gateway is running</p>
            <p>Robust multilingual security gateway<br>for LLM applications</p>
            <br>
            <a href="/docs">Swagger UI</a>
            <a href="/health">Health Check</a>
            <a href="/audit">Audit Log</a>
        </div>
    </body>
    </html>
    """

# ── Main Analysis Endpoint ────────────────────────────────
@app.post("/analyze")
def analyze(text: str = Query(..., description="Input text to analyze")):
    """
    Analyzes input text through the full security pipeline.

    Pipeline:
    1. Language detection
    2. Rule-based injection detection (English + Urdu + Korean)
    3. Semantic/ML injection detection (TF-IDF + Logistic Regression)
    4. Presidio PII detection and anonymization
    5. Policy engine (ALLOW / MASK / BLOCK)
    6. Audit logging

    Returns a full JSON audit record.
    """
    total_start = time.time()

    # Generate unique ID for this request
    input_id = f"case_{uuid.uuid4().hex[:6]}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Step 1 — Language Detection
    language = detect_language(text)

    # Step 2 — Rule-Based Detection
    rule_result = detect_injection(text)

    # Step 3 — Semantic Detection
    semantic_result = detect_semantic(text)

    # Step 4 — PII Analysis
    pii_result = analyze_pii(text)

    # Step 5 — Policy Decision
    policy_result = make_decision(rule_result, semantic_result, pii_result)

    # Total latency
    total_latency = round((time.time() - total_start) * 1000, 3)

    # ── Build Response ────────────────────────────────────
    response = {
        "input_id":       input_id,
        "timestamp":      timestamp,
        "input":          text,
        "language":       language,
        "rule_score":     rule_result["rule_score"],
        "semantic_score": semantic_result["semantic_score"],
        "pii_entities":   pii_result["entities_found"],
        "composite_risks": pii_result["composite_risks"],
        "final_risk":     policy_result["final_risk"],
        "decision":       policy_result["decision"],
        "safe_text":      policy_result["safe_text"],
        "reason":         policy_result["reason"],
        "reason_codes":   policy_result["reason_codes"],
        "matched_patterns": rule_result["matched_patterns"],
        "latency_ms":     total_latency,
    }

    # Step 6 — Write Audit Log
    write_audit_log(response)

    return JSONResponse(content=response)

# ── Health Check ──────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "2.0",
        "thresholds": POLICY_SETTINGS,
    }

# ── Audit Log Viewer ──────────────────────────────────────
@app.get("/audit", response_class=HTMLResponse)
def get_audit_log(last: int = 20):
    """Returns the last N audit log entries as a clean HTML table."""

    records = []
    total = 0
    if os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        total = len(lines)
        for line in lines[-last:]:
            try:
                records.append(json.loads(line.strip()))
            except Exception:
                pass

    rows_html = ""
    for r in reversed(records):
        decision = r.get("decision", "")
        color = {"ALLOW": "#22c55e", "MASK": "#f59e0b", "BLOCK": "#ef4444"}.get(decision, "#888")
        badge = f'<span style="background:{color};color:white;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600">{decision}</span>'
        codes = ", ".join(r.get("reason_codes", [])) or "—"
        lang  = r.get("language", "—")
        risk  = r.get("final_risk", "—")
        rule  = r.get("rule_score", "—")
        sem   = r.get("semantic_score", "—")
        lat   = r.get("latency_ms", "—")
        inp   = r.get("input", "")[:60] + ("..." if len(r.get("input","")) > 60 else "")
        ts    = r.get("timestamp", "")[:19].replace("T", " ")

        rows_html += f"""
        <tr>
            <td style="color:#888;font-size:12px">{ts}</td>
            <td style="max-width:280px;word-break:break-word">{inp}</td>
            <td style="text-align:center">{lang}</td>
            <td style="text-align:center">{rule}</td>
            <td style="text-align:center">{sem}</td>
            <td style="text-align:center;font-weight:600">{risk}</td>
            <td style="text-align:center">{badge}</td>
            <td style="font-size:12px;color:#6c63ff">{codes}</td>
            <td style="text-align:center;color:#888">{lat} ms</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="9" style="text-align:center;color:#888;padding:32px">No requests logged yet. Send something to /analyze first!</td></tr>'

    return f"""
    <html>
    <head>
        <title>Audit Log — LLM Gateway</title>
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; padding: 32px; }}
            h2 {{ color: #6c63ff; margin-bottom: 4px; }}
            .meta {{ color: #888; font-size: 13px; margin-bottom: 24px; }}
            .card {{ background: white; border-radius: 16px; padding: 24px; box-shadow: 0 4px 24px rgba(0,0,0,0.07); overflow-x: auto; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            th {{ background: #6c63ff; color: white; padding: 10px 14px; text-align: left; font-weight: 600; }}
            tr:nth-child(even) {{ background: #f9f9fb; }}
            td {{ padding: 10px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }}
            tr:hover {{ background: #f0eeff; }}
            .back {{ display:inline-block; margin-bottom:20px; color:#6c63ff; text-decoration:none; font-weight:500; }}
        </style>
    </head>
    <body>
        <a class="back" href="/">← Back to Gateway</a>
        <h2>📋 Audit Log</h2>
        <p class="meta">Total logged: <b>{total}</b> requests &nbsp;|&nbsp; Showing last <b>{min(last, total)}</b></p>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Input</th>
                        <th>Lang</th>
                        <th>Rule</th>
                        <th>Semantic</th>
                        <th>Risk</th>
                        <th>Decision</th>
                        <th>Reason Codes</th>
                        <th>Latency</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

# ── Stats Endpoint ────────────────────────────────────────
@app.get("/stats")
def get_stats():
    """Returns summary statistics from audit log."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return {"message": "No audit log found yet."}

    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    allow = mask = block = 0
    for line in lines:
        try:
            r = json.loads(line.strip())
            d = r.get("decision", "")
            if d == "ALLOW":  allow += 1
            elif d == "MASK": mask  += 1
            elif d == "BLOCK": block += 1
        except Exception:
            pass

    total = allow + mask + block
    return {
        "total_requests": total,
        "ALLOW":  allow,
        "MASK":   mask,
        "BLOCK":  block,
    }