#!/usr/bin/env python3
"""
DeQode Web Application — Flask Backend
Provides a web-based UI for QR code phishing detection
"""

import os
import json
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# ── Setup ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

# Load API Key from .env
VT_API_KEY = ""
env_path = BASE_DIR / ".env"
if env_path.exists():
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("VT_API_KEY="):
                VT_API_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

if not VT_API_KEY:
    VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

# ── Import modules ──────────────────────────────────────────────────────────
from modules.decoder import decode_qr_from_image
from modules.network import resolve_url
from modules.url_inspector import analyze_url
from modules.reputation import check_virustotal

# ── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_final_verdict(heuristic_verdict, vt_verdict):
    """Combine heuristic + VT results into one overall verdict."""
    danger = {"MALICIOUS", "SUSPICIOUS"}
    if heuristic_verdict in danger or vt_verdict in danger:
        if heuristic_verdict == "MALICIOUS" or vt_verdict == "MALICIOUS":
            return "MALICIOUS"
        return "SUSPICIOUS"
    return "SAFE"


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'DeQode API',
        'vt_key_loaded': bool(VT_API_KEY and len(VT_API_KEY) >= 32)
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyze uploaded QR code image
    
    Expected: POST request with file upload
    Returns JSON with analysis results
    """
    
    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: PNG, JPG, GIF, BMP, WebP'}), 400
    
    try:
        # Save uploaded file to temporary location
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)
        
        # ── Decode QR Codes ──────────────────────────────────────────────
        urls = decode_qr_from_image(temp_path)
        
        if not urls:
            # Clean up temp file
            try:
                os.remove(temp_path)
            except:
                pass
            return jsonify({'error': 'No QR code found in image'}), 400
        
        # ── Analyze each URL ─────────────────────────────────────────────
        results = []
        
        for raw_url in urls:
            result = {
                'original_url': raw_url,
                'final_url': raw_url,
                'redirect_detected': False,
                'heuristic_verdict': 'UNKNOWN',
                'heuristic_score': 0,
                'heuristic_flags': [],
                'vt_verdict': 'UNKNOWN',
                'vt_detections': 0,
                'vt_engines': 0,
                'status_code': None,
                'network_error': None,
                'overall_verdict': 'UNKNOWN'
            }
            
            # Step 1: Resolve URL redirects
            net_result = resolve_url(raw_url)
            net_error = net_result.get("error")
            final_url = net_result.get("final_url") or raw_url
            status_code = net_result.get("status_code")
            
            result['final_url'] = final_url
            result['status_code'] = status_code
            
            if net_error:
                result['network_error'] = net_error
                if final_url != raw_url:
                    result['redirect_detected'] = True
            else:
                if final_url != raw_url:
                    result['redirect_detected'] = True
            
            # Step 2: Heuristic analysis on resolved URL
            heuristic = analyze_url(final_url)
            h_verdict = heuristic.get("verdict", "UNKNOWN")
            h_score = heuristic.get("risk_score", 0)
            flags = heuristic.get("flags", [])
            
            result['heuristic_verdict'] = h_verdict
            result['heuristic_score'] = h_score
            result['heuristic_flags'] = flags
            
            # Step 3: VirusTotal check
            vt_verdict = "UNKNOWN"
            vt_detections = 0
            vt_engines = 0
            
            if VT_API_KEY and len(VT_API_KEY) >= 32:
                vt = check_virustotal(final_url, VT_API_KEY)
                if not vt.get("error"):
                    vt_verdict = vt.get("verdict", "UNKNOWN")
                    vt_detections = vt.get("malicious", 0)
                    vt_engines = vt.get("total_engines", 0)
            
            result['vt_verdict'] = vt_verdict
            result['vt_detections'] = vt_detections
            result['vt_engines'] = vt_engines
            
            # Step 4: Final combined verdict
            overall_verdict = get_final_verdict(h_verdict, vt_verdict)
            result['overall_verdict'] = overall_verdict
            
            results.append(result)
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass
        
        # Return results
        return jsonify({
            'qr_count': len(urls),
            'results': results,
            'success': True
        }), 200
        
    except Exception as e:
        # Clean up temp file on error
        try:
            os.remove(temp_path)
        except:
            pass
        
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


# ── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large errors"""
    return jsonify({'error': 'File too large. Maximum size: 16MB'}), 413


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 54)
    print("        DeQode: QR Phishing Detector Web UI")
    print("=" * 54)
    
    if VT_API_KEY and len(VT_API_KEY) >= 32:
        print(f"[✓] VirusTotal API Key loaded ({VT_API_KEY[:6]}...{VT_API_KEY[-4:]})")
    else:
        print("[!] Warning: VirusTotal API key not found")
    
    print("\n[*] Starting Flask server...")
    print("[*] Open your browser to: http://localhost:5000")
    print("=" * 54 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
