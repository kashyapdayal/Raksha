# **Suraksha** 
A secure, offline, terminal-based password manager written in Python.  
It stores your passwords in **encrypted form** on your local Linux machine — no cloud storage, no trackers, no spying.  
It uses **AES-256 encryption via `cryptography` library** and provides **master password protection** with recovery options.

##  Features

- **Local Storage Only** – Data stored in `~/.password_vault` with `chmod 700` permissions.
- **AES-256 Encryption** – Secured with `cryptography.fernet` and PBKDF2 key derivation.
- **Master Password Protection** – Access all saved credentials with one strong password.
- **Strong Password Validation** – Uses `zxcvbn` to enforce secure master passwords.
- **Password Categories** – Store passwords under `private` or `business`.
- **Password Recovery** – Multiple recovery questions, phone & email verification.
- **Colorful CLI Interface** – Enhanced visuals with `termcolor` and `pyfiglet`.
- **Secure Input** – Passwords entered via `getpass` (hidden typing).
- **Offline and Open Source** – No internet required after installation.

---

# Installation
1️⃣ Clone the Repository
```
git clone https://github.com/Kashyap7225/Suraksha.git
cd suraksha
```
2️⃣ Install Dependencies
Make sure you have Python 3.8+ installed, then run:
```
pip install -r requirements.txt
```
### Dependencies included in requirements.txt:
> cryptography

> termcolor

> pyfiglet

> zxcvbn

> pyperclip

> pyautogui

## Run the application:
```
python3 suraksha.py
```
##  Menu Options
=> Add Password
Save a new password under either private or business category.

=> View Passwords
View stored passwords in a colorful table.

=> Delete Password
Remove a saved password from your vault.

=> Master Password Management
Change Master Password
Recover Forgotten Password

=> Setup Recovery
Update recovery questions, phone, and email.

=> Exit
Close the program.

# Project Structure
```
suraksha/
│-- suraksha.py        # Main program
│-- requirements.txt   # Dependencies
│-- README.md          # Documentation
└── (created after first run)
    ~/.password_vault/
        ├── secure_passwords.enc
        ├── salt
        └── recovery.json
```
