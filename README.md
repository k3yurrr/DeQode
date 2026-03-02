# DeQode — QR Phishing Detector

A Python tool that detects malicious QR codes using heuristic analysis and VirusTotal threat intelligence.

## Features
- Decodes QR codes from image files
- Unmasks shortened/redirected URLs
- Heuristic analysis (TLD, keywords, SSL, structure)
- VirusTotal API integration (94 engines)
- Desktop GUI with colour-coded verdicts

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Add your VirusTotal API key to a `.env` file:
```
VT_API_KEY=your_key_here
```

## Usage
```bash
# CLI
python3 main.py

# GUI
python3 gui.py
```

## Stack
Python · OpenCV · pyzbar · Requests · VirusTotal API · Tkinter
