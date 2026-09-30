# SecureAuth – Simple Login and Registration System

A beginner-friendly Flask web app demonstrating secure user registration, login, logout and password handling.

## Features
- User registration with validation (username, email, password strength, duplicate detection)
- Password hashing (Werkzeug PBKDF2) – plain-text passwords are never stored
- Login with username or email, session-based authentication
- Account lockout after 5 failed attempts (5 minutes)
- Session timeout (15 minutes), HttpOnly + SameSite cookies
- CSRF protection (Flask-WTF), parameterized SQL queries (SQL injection safe)
- Protected dashboard, change-password page, POST-only logout

## Tech Stack
Python · Flask · SQLite · HTML · Bootstrap 5 · Flask-WTF

## Run locally
```bash
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Project structure
```
app.py            # routes, validation, DB logic
templates/        # base, register, login, dashboard, change_password
requirements.txt
```
