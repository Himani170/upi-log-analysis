from flask import Flask, render_template, request, jsonify
from fraud_detector import UPIRiskChecker, FraudDetector
app = Flask(__name__)
# Initialize checkers
upi_checker = UPIRiskChecker()
fraud_detector = FraudDetector()
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/check-upi', methods=['POST'])
def check_upi():
    upi_id = request.form.get('upi_id', '').strip()
    if not upi_id:
        return render_template('result.html', error="Please enter a UPI ID")
    # Analyze the UPI ID
    result = upi_checker.analyze_upi_id(upi_id)
    return render_template('result.html', 
                         upi_id=result['upi_id'],
                         risk_level=result['risk_level'],
                         risk_score=result['risk_score'],
                         reasons=result['reasons'],
                         bank_handle=result['bank_handle'],
                         is_trusted_bank=result['is_trusted_bank'])
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
@app.route('/report')
def report():
    return render_template('report.html')
# API endpoint for JSON
@app.route('/api/check-upi', methods=['POST'])
def api_check_upi():
    data = request.get_json()
    result = upi_checker.analyze_upi_id(data.get('upi_id', ''))
    return jsonify(result)
if __name__ == '__main__':
    app.run(debug=True)