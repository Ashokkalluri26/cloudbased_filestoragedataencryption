# SecureCloud - Enterprise File Storage Platform

A secure cloud file storage platform with AES-256 encryption, built with Python Flask and MySQL/SQLite.

## Features
- **AES-256 Encryption** - Military-grade file encryption
- **User Authentication** - Secure login with 2FA support
- **File Management** - Upload, download, share files securely
- **Zero-Knowledge** - Files encrypted before upload
- **MySQL/SQLite** - Flexible database options

## Screenshots

### Landing Page
![Landing Page](https://github.com/Ashokkalluri26/cloudbased_filestoragedataencryption/blob/main/screenshots/home1.png)

### User Registration
![Registration Page](https://github.com/Ashokkalluri26/cloudbased_filestoragedataencryption/blob/main/screenshots/create1.png)

### User Login
![Login Page](https://github.com/Ashokkalluri26/cloudbased_filestoragedataencryption/blob/main/screenshots/login.png)

## Quick Start

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Run Application**
```bash
# MySQL version
python run_mysql.py

# SQLite version  
python app_sqlite.py
```

3. **Access Application**
Open `http://localhost:5000` in your browser

## Tech Stack
- **Backend**: Python Flask, SQLAlchemy
- **Database**: MySQL/SQLite
- **Frontend**: Jinja2, Bootstrap 5, TailwindCSS
- **Security**: AES-256 encryption, Flask-Login, PyOTP
