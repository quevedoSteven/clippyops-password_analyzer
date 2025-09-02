from flask import Flask, render_template, request, jsonify, session
import json
import time
from config import config
from models import PasswordAnalysis, BreachResult
from services import PasswordAnalyzerService, BreachCheckerService, EncryptionService
from utils import InputValidator

app = Flask(__name__)
app.config.from_object(config['default'])

analyzer_service = PasswordAnalyzerService()
breach_service = BreachCheckerService()
encryption_service = EncryptionService()

@app.route('/')
def index():
    session['session_token'] = encryption_service.generate_secure_token()
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/analyze', methods=['POST'])
def analyze_password():
    password = request.form.get('password', '')
    
    is_valid, error = InputValidator.validate_password_input(password)
    if not is_valid:
        return render_template('analysis.html', error=error)
    
    analysis_result = analyzer_service.analyze_password(password)
    breach_result = breach_service.check_password_breach(password)
    
    return render_template('analysis.html', 
                         analysis=analysis_result, 
                         breach=breach_result)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    
    is_valid, error = InputValidator.validate_analysis_request(data)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    password = data.get('password', '')
    
    analysis_result = analyzer_service.analyze_password(password)
    breach_result = breach_service.check_password_breach(password)
    
    return jsonify({
        'analysis': analysis_result.to_dict(),
        'breach': breach_result.to_dict(),
        'timestamp': time.time(),
        'session_id': session.get('session_token')
    })

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    data = request.get_json()
    length = data.get('length', 16)
    
    if not isinstance(length, int) or length < 12 or length > 64:
        length = 16
    
    secure_password = encryption_service.generate_secure_token()[:length]
    return jsonify({'password': secure_password})

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/api/security-intelligence')
def security_intelligence():
    intelligence = breach_service.get_security_intelligence()
    return jsonify(intelligence)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)