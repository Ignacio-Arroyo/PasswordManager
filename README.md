# Password Manager

A simple cross-platform desktop Password Manager built with PyQt5.  
Features include user registration/login, TOTP-based 2FA (QR code setup), storing credentials (website, username, password), viewing, editing, deleting credentials, and a password generator.

## Features
- User registration and login
- Two-Factor Authentication (TOTP) with QR code provisioning
- Add, view, edit, and delete stored credentials
- Password generator
- Local SQLite database (created automatically)

## Requirements
- Python 3.7+
- PyQt5
- pyotp
- qrcode
- pillow (required by qrcode)
- (Optional) Any other dependencies referenced in your environment

Install dependencies:
```
pip install PyQt5 pyotp qrcode pillow
```

## Running the app
1. Ensure dependencies are installed.
2. From the project root, run:
```
python app.py
```
3. Use the Register screen to create a new user. After registration you will be prompted to set up 2FA by scanning the displayed QR code with an authenticator app (e.g., Google Authenticator, Authy).
4. Log in with your credentials and the TOTP code from your authenticator app.
5. Add and manage your credentials in the main window.

## Database
- The app initializes a local SQLite database using the helper functions in `database_operations` (called by `create_database()`).
- Credentials are associated with the registered user.

## Security notes & recommendations
- This project is a learning/demo implementation. By default, passwords appear to be stored without encryption in the provided code. For production use:
  - Hash user passwords with a secure algorithm (e.g., bcrypt, Argon2) for authentication.
  - Encrypt stored credentials (e.g., using a master encryption key derived from a strong passphrase).
  - Securely store TOTP secrets and use OS-provided secure storage when possible.
  - Consider adding automatic logout, password strength checks, and secure backup/restore.
- Do not use this implementation to store sensitive data without applying proper encryption and security hardening.

## Project structure (important files)
- app.py — Main application code and UI (PyQt5)
- database_operations.py — Database helpers (create database, insert/fetch/update/delete, user and 2FA helpers)
- qrcode images for 2FA are generated temporarily as `qrcode_user_<id>.png`.

## Contributing
Contributions and improvements are welcome. Please open issues or pull requests for enhancements, especially around security and data encryption.

## License
Add a license of your choice (e.g., MIT) in a LICENSE file if you intend to distribute this project.

## PasswordManager

# How to create an environment :

python -m venv myenv


# How to activate the environment :
Linux
source myenv/bin/activate

Windows
myenv\Scripts\activate

# How to desactivate the environment : 

deactivate

# Packages installed : 
- cryptography
- PyQt
- pyperclip
- passlib

# How to list installed python packages : 

pip list

# Export the used packages into a requirement.txt : 

pip freeze > requirements.txt
