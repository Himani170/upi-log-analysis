from flask import Flask, render_template, request, jsonify, send_file, redirect
import os, io, datetime

from backend.fraud_detector import analyze_upi, check_email_breach, scan_url_virustotal
from backend.breach_db      import analyze_password
from backend.database       import init_db, save_report, get_all_reports, clear_all_reports, save_url_scan, get_all_url_scans
from backend.charts         import generate_charts

app = Flask(__name__)
app.secret_key = "upi_hacker_secret_2025"

init_db()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/check-upi', methods=['POST'])
def check_upi():
    try:
        data   = request.get_json()
        upi    = data.get("upi_id", "").strip()
        if not upi:
            return jsonify({"error": "No UPI ID provided"}), 400
        result = analyze_upi(upi)
        save_report(upi, result["score"], result["verdict"], ", ".join(result["reasons"]))
        generate_charts(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/check-breach', methods=['POST'])
def check_breach():
    try:
        data   = request.get_json()
        target = data.get("target", "").strip()
        result = check_email_breach(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    try:
        data = request.get_json()
        pw   = data.get("password", "")
        if not pw:
            return jsonify({"error": "No password provided"}), 400
        result = analyze_password(pw)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan-url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        url  = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        result = scan_url_virustotal(url)
        verdict_text = result.get("message", "Unknown")
        save_url_scan(
            url=result.get("url", url),
            verdict=verdict_text,
            malicious=result.get("malicious", 0),
            suspicious=result.get("suspicious", 0),
            total=result.get("total", 0),
            tip=result.get("tip", "")
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/dashboard')
def dashboard():
    rows      = get_all_reports()
    url_rows  = get_all_url_scans()
    safe      = sum(1 for r in rows if r[3] == "SAFE")
    susp      = sum(1 for r in rows if r[3] == "SUSPICIOUS")
    fraud     = sum(1 for r in rows if r[3] == "FRAUD")
    return render_template("dashboard.html", history=rows, url_history=url_rows,
                           safe=safe, susp=susp, fraud=fraud)

@app.route('/export')
def export_page():
    rows      = get_all_reports()
    url_rows  = get_all_url_scans()
    safe      = sum(1 for r in rows if r[3] == "SAFE")
    susp      = sum(1 for r in rows if r[3] == "SUSPICIOUS")
    fraud     = sum(1 for r in rows if r[3] == "FRAUD")
    url_danger = sum(1 for r in url_rows if r[2] and ("DANGEROUS" in r[2] or "SUSPICIOUS" in r[2]))
    return render_template("export.html",
                           total=len(rows), url_total=len(url_rows),
                           safe=safe, susp=susp, fraud=fraud,
                           url_danger=url_danger)

@app.route('/download-pdf')
def download_pdf():
    from backend.report import generate_pdf
    export_type = request.args.get('type', 'both')
    upi_rows  = get_all_reports()
    url_rows  = get_all_url_scans()
    buf       = generate_pdf(upi_rows, url_rows, export_type=export_type)
    label     = {'upi': 'upi_fraud', 'links': 'link_scanner', 'both': 'full_report'}.get(export_type, 'full_report')
    filename  = f"upiguard_{label}_{datetime.date.today()}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/pdf')

@app.route('/export-pdf')
def export_pdf_legacy():
    return redirect('/export')

@app.route('/clear-history', methods=['POST'])
def clear_history():
    try:
        clear_all_reports()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
