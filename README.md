# 🛡️ StegoShield — Forensic Steganography Platform

> A research-grade cybersecurity tool for image steganography detection, threat analysis, and secure data embedding using AES-256-GCM encryption.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-red)

---

## 📋 Table of Contents
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Deployment](#-deployment)
- [Project Structure](#-project-structure)
- [Screenshots](#-screenshots)

---

## ✨ Features

### 🔐 Secure Data Embedding
- **AES-256-GCM** authenticated encryption with PBKDF2 key derivation (100,000 iterations)
- LSB (Least Significant Bit) steganographic embedding into carrier images
- Support for any file format as payload (PDF, DOCX, ZIP, etc.)

### 🔬 10-Layer Forensic Scanner
| Layer | Analysis | Tool |
|-------|----------|------|
| 1 | File Integrity Validation | PIL / filetype |
| 2 | EXIF Metadata Parsing | ExifTool |
| 3 | Statistical Steganalysis | OpenCV |
| 4 | LSB Bit-plane Analysis | NumPy |
| 5 | Shannon Entropy Mapping | Custom |
| 6 | YARA Signature Matching | yara-python |
| 7 | Antivirus Scanning | ClamAV |
| 8 | AI Threat Prediction | TensorFlow |
| 9 | Payload Carving | Binwalk / zsteg |
| 10 | Risk Classification (0-100) | Scoring Engine |

### 📊 SOC-Grade Dashboard
- Real-time threat intelligence overview with Chart.js visualizations
- Risk distribution and operation activity charts
- Full scan history with on-demand forensic report access

### 👥 Role-Based Access Control
- **Admin**: Full forensic breakdown, YARA hits, AI predictions, entropy data
- **Standard User**: Summary view with threat score and risk level only

---

## 🏗️ Architecture

```
Client Browser ──► Flask Web Server ──► 10-Layer Pipeline ──► SQLite DB
     │                    │                     │
     │              Auth Manager          External Tools
     │            (Flask-Login)         (ExifTool, ClamAV,
     │                                  YARA, Binwalk)
     │
     └──► Chart.js Dashboard
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Backend | Python 3.11, Flask 3.0 |
| Database | SQLite + SQLAlchemy ORM |
| Auth | Flask-Login, Werkzeug (PBKDF2) |
| Encryption | `cryptography` library (AES-256-GCM) |
| Forensics | OpenCV, NumPy, PIL, yara-python |
| AI Engine | TensorFlow 2.15 |
| Frontend | HTML5, CSS3 (Custom Dark Theme), JavaScript ES6 |
| Charts | Chart.js |
| Icons | Font Awesome 6 |
| Server | Gunicorn (Production) |

---

## 🚀 Installation

### Prerequisites
- Python 3.9+ installed
- Git installed

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/StegoShield.git
cd StegoShield

# 2. Create virtual environment
python -m venv venv

# 3. Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Set up environment variables
cp .env.example .env
# Edit .env with your SECRET_KEY

# 6. Run the application
python app.py
```

The app will be available at: `http://127.0.0.1:5000`

### First-Time Setup
1. Navigate to `/register`
2. The **first registered user** is automatically an **Admin**
3. Subsequent users need the `ADMIN_KEY` to register as admin

---

## ☁️ Deployment

### Deploy on Render.com (Recommended — Free Tier)

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → **New** → **Web Service**
3. Connect your GitHub repository
4. Render will auto-detect `render.yaml` and configure everything
5. Click **Deploy** — your app will be live in ~3 minutes

### Environment Variables (set in Render dashboard)
| Variable | Value |
|----------|-------|
| `SECRET_KEY` | Auto-generated |
| `ADMIN_KEY` | Your custom admin registration key |
| `DATABASE_URL` | `sqlite:///stego.db` |
| `FLASK_ENV` | `production` |

---

## 📁 Project Structure

```
StegoShield/
├── app.py                  # Application factory & startup
├── config.py               # Configuration (env-based)
├── models.py               # Database models (User, ScanRecord)
├── requirements.txt        # Python dependencies
├── Procfile                # Production server command
├── render.yaml             # Render.com auto-deploy config
├── .env.example            # Environment variable template
├── .gitignore              # Git exclusion rules
│
├── routes/
│   ├── auth_routes.py      # Login / Register / Logout
│   ├── main_routes.py      # Dashboard, History, API endpoints
│   ├── encrypt_routes.py   # Encryption & embedding logic
│   ├── decrypt_routes.py   # Decryption & extraction logic
│   └── scan_routes.py      # Forensic scanning endpoint
│
├── services/
│   ├── scan_service.py     # 10-layer pipeline orchestrator
│   ├── stego_service.py    # LSB embedding/extraction
│   ├── ai_service.py       # TensorFlow threat prediction
│   ├── yara_service.py     # YARA rule matching
│   ├── metadata_service.py # EXIF metadata analysis
│   ├── steganalysis_service.py  # Statistical analysis
│   ├── extraction_service.py    # Payload carving
│   └── validation_service.py    # File integrity checks
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Layout with sidebar & topbar
│   ├── login.html          # Authentication page
│   ├── register.html       # User registration
│   ├── upload.html         # Encrypt / Decrypt / Scan hub
│   ├── dashboard.html      # Admin threat intelligence
│   └── history.html        # Scan history log
│
├── static/
│   └── style.css           # SOC dark-mode theme
│
├── rules/                  # YARA malware detection rules
└── uploads/                # File storage (auto-created)
    ├── stego/
    ├── extracted/
    └── encrypted/
```

---

## 🔒 Security Notes

- **Never commit `.env`** — it contains your secret keys
- The `SECRET_KEY` should be a random 64-character hex string
- Change the default `ADMIN_KEY` before going live
- The SQLite database (`stego.db`) is excluded from Git

---

## 📄 License

This project was developed as a Final Year Project (FYP) for academic research purposes.

---

## 👨‍💻 Author

**Saad Khan** — Cybersecurity Research  
📧 saadrkhann074@gmail.com
