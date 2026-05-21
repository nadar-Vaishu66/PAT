"""
PAT - Password Analysis Tool
Flask Backend
"""

from flask import Flask, render_template, request, jsonify
from utils.analyzer import analyze_password
from utils.generator import generate_password, generate_passphrase
import hashlib
import requests
import os

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Real-time password analysis endpoint."""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = analyze_password(password)
    return jsonify(result)


@app.route('/api/breach-check', methods=['POST'])
def breach_check():
    """Check if password appears in known breaches via HaveIBeenPwned API."""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    try:
        # Hash password with SHA1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query HIBP k-anonymity API
        response = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'PAT-PasswordAnalysisTool'},
            timeout=5
        )
        
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for line in hashes:
                parts = line.split(':')
                if len(parts) == 2 and parts[0].upper() == suffix:
                    count = int(parts[1])
                    return jsonify({
                        'breached': True,
                        'count': count,
                        'message': f'WARNING: This password has appeared in {count:,} known data breaches.'
                    })
            return jsonify({'breached': False, 'count': 0, 'message': 'No breaches found in known databases.'})
        else:
            return jsonify({'breached': None, 'error': 'Unable to reach breach database.'})
    
    except requests.exceptions.Timeout:
        return jsonify({'breached': None, 'error': 'Breach database check timed out.'})
    except requests.exceptions.ConnectionError:
        return jsonify({'breached': None, 'error': 'Could not connect to breach database.'})
    except Exception as e:
        return jsonify({'breached': None, 'error': str(e)})


@app.route('/api/generate', methods=['POST'])
def generate():
    """Generate a secure password."""
    data = request.get_json()
    length = int(data.get('length', 16))
    use_symbols = data.get('symbols', True)
    use_numbers = data.get('numbers', True)
    use_uppercase = data.get('uppercase', True)
    use_memorable = data.get('memorable', False)
    
    # Clamp length
    length = max(8, min(64, length))
    
    if use_memorable:
        result = generate_passphrase()
    else:
        result = generate_password(length, use_symbols, use_numbers, use_uppercase)
    
    # Also analyze the generated password
    analysis = analyze_password(result)
    
    return jsonify({
        'password': result,
        'analysis': analysis
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)