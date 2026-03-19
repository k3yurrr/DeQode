#!/usr/bin/env python3
"""
DeQode Web Application — Flask Backend
Optimized for Vercel Serverless Deployment
"""

import os
import json
import tempfile
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# ── Setup ────────────────────────────────────────────────────────────────────
# Use absolute path resolution for Vercel's read-only environment
BASE_DIR = Path(__file__).resolve().parent
# Vercel allows writing ONLY to /tmp
UPLOAD_FOLDER = "/tmp" 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

# ── Flask App ────────────────────────────────────────────────────────────────
# Explicitly set template folder using an absolute path
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ── API Key Logic ────────────────────────────────────────────────────────────
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

# Fallback to .env only if not in environment variables (useful for local dev)
if not VT_API_KEY:
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                if line.startswith("VT_API_KEY="):
                    VT_API_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
                    
# Push it to system env so reputation.py can find it automatically
if VT_API_KEY:
    os.environ["VT_API_KEY"] = VT_API_KEY

# ── Import modules ──────────────────────────────────────────────────────────
# Ensure these modules are in your repository structure
from modules.decoder import decode_qr_from_image
from modules.network import resolve_url
from modules.url_inspector import analyze_url
from modules.reputation import check_virustotal

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_final_verdict(heuristic_verdict, vt_verdict):
    danger = {"MALICIOUS", "SUSPICIOUS"}
    if heuristic_verdict in danger or vt_verdict in danger:
        if heuristic_verdict == "MALICIOUS" or vt_verdict == "MALICIOUS":
            return "MALICIOUS"
        return "SUSPICIOUS"
    return "SAFE"

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'DeQode API',
        'vt_key_loaded': bool(VT_API_KEY and len(VT_API_KEY) >= 32)
    })

@app.route('/api/info', methods=['GET'])
def info():
    """Get app information including last updated time"""
    try:
        app_file = BASE_DIR / 'app.py'
        last_modified = os.path.getmtime(app_file)
        last_updated = datetime.fromtimestamp(last_modified).strftime('%Y-%m-%d %H:%M:%S')
    except:
        last_updated = 'Unknown'
    
    return jsonify({
        'version': '1.0',
        'last_updated': last_updated
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    temp_path = None
    try:
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)
        
        urls = decode_qr_from_image(temp_path)
        
        if not urls:
            return jsonify({'error': 'No QR code found'}), 400
        
        results = []
        for raw_url in urls:
            result = {
                'original_url': raw_url,
                'final_url': raw_url,
                'redirect_detected': False,
                'heuristic_verdict': 'UNKNOWN',
                'vt_verdict': 'UNKNOWN',
                'overall_verdict': 'UNKNOWN',
                'heuristic_score': 0,
                'heuristic_flags': [],
                'vt_detections': 0,
                'vt_engines': 0,
                'network_error': None
            }
            
            # 1. Resolve
            net_result = resolve_url(raw_url)
            final_url = net_result.get("final_url") or raw_url
            result['final_url'] = final_url
            result['status_code'] = net_result.get("status_code")
            result['redirect_detected'] = (final_url != raw_url)
            if net_result.get("error"):
                result['network_error'] = net_result.get("error")
            
            # 2. Heuristics
            heuristic = analyze_url(final_url)
            result['heuristic_verdict'] = heuristic.get("verdict", "UNKNOWN")
            # --- FIX: Pass the score and flags to the frontend ---
            result['heuristic_score'] = heuristic.get("risk_score", 0)
            result['heuristic_flags'] = heuristic.get("flags", [])
            
            # 3. VirusTotal
            if VT_API_KEY and len(VT_API_KEY) >= 32:
                # FIX: Passed VT_API_KEY back into the function!
                vt = check_virustotal(final_url, VT_API_KEY)
                
                if vt.get("error"):
                    result['vt_verdict'] = "UNKNOWN"
                else:
                    # --- FIX: Pass VT engine counts to the frontend ---
                    detections = vt.get("malicious", 0) + vt.get("suspicious", 0)
                    total_scanned = vt.get("total_scanned", 0)
                    
                    result['vt_detections'] = detections
                    result['vt_engines'] = total_scanned
                    result['vt_verdict'] = "MALICIOUS" if detections > 0 else "SAFE"
            
            # 4. Verdict
            result['overall_verdict'] = get_final_verdict(result['heuristic_verdict'], result['vt_verdict'])
            results.append(result)
        
        return jsonify({'qr_count': len(urls), 'results': results, 'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        # Final cleanup attempt
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

# ── Entry Point ──────────────────────────────────────────────────────────────
# Vercel ignores the __main__ block, which is perfect for serverless.
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)