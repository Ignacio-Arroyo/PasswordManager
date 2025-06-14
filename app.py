import sys
import random
import string
import pyotp
import qrcode
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit,
                            QPushButton, QMessageBox, QListWidget, QHBoxLayout, QStackedWidget,
                            QInputDialog, QDialog, QDialogButtonBox, QFormLayout)
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtCore import Qt
from database_operations import (
    create_database, insert_credential, fetch_credentials, fetch_password,
    verify_user, register_user, get_user_id, get_2fa_secret, update_credential, delete_credential
)

class LoginWindow(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget

        layout = QVBoxLayout()

        title = QLabel("Password Manager")
        title.setFont(QFont('Arial', 20))
        title.setAlignment(Qt.AlignCenter)

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.login_button.setStyleSheet("background-color: #4CAF50; color: white;")

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        self.register_button.setStyleSheet("background-color: #2196F3; color: white;")

        layout.addWidget(title)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if verify_user(username, password):
            user_id = get_user_id(username)
            token, ok = QInputDialog.getText(self, 'Two-Factor Authentication', 'Enter your 2FA token:')

            if ok:
                secret_key = get_2fa_secret(user_id)
                if secret_key:
                    totp = pyotp.TOTP(secret_key)
                    if totp.verify(token):
                        QMessageBox.information(self, "Login", "Login Successful!")
                        self.stacked_widget.setCurrentIndex(2)
                        self.stacked_widget.currentWidget().set_user_id(user_id)
                    else:
                        QMessageBox.warning(self, "Login", "Invalid 2FA token.")
                else:
                    QMessageBox.warning(self, "Login", "2FA not set up for this user.")
        else:
            QMessageBox.warning(self, "Login", "Invalid username or password.")

class RegisterWindow(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget

        layout = QVBoxLayout()

        title = QLabel("Register")
        title.setFont(QFont('Arial', 20))
        title.setAlignment(Qt.AlignCenter)

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register)
        self.register_button.setStyleSheet("background-color: #4CAF50; color: white;")

        layout.addWidget(title)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if username and password:
            secret_key = register_user(username, password)
            if secret_key:
                QMessageBox.information(self, "Register", "Registration Successful! Please set up 2FA.")
                self.setup_2fa(get_user_id(username))
                self.stacked_widget.setCurrentIndex(0)
            else:
                QMessageBox.warning(self, "Register", "Username already exists!")
        else:
            QMessageBox.warning(self, "Register", "Please enter both username and password.")

    def setup_2fa(self, user_id):
        secret_key = get_2fa_secret(user_id)
        if secret_key:
            totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=f"user_{user_id}@passwordmanager.com", issuer_name="PasswordManager")
            img = qrcode.make(totp_uri)
            img.save(f"qrcode_user_{user_id}.png")

            qr_dialog = QDialog(self)
            qr_dialog.setWindowTitle("QR Code for 2FA Setup")
            qr_dialog.setGeometry(100, 100, 300, 300)

            qr_label = QLabel(qr_dialog)
            qr_pixmap = QPixmap(f"qrcode_user_{user_id}.png")
            qr_label.setPixmap(qr_pixmap)

            layout = QVBoxLayout()
            layout.addWidget(QLabel("Scan the QR code with your authenticator app:"))
            layout.addWidget(qr_label)
            qr_dialog.setLayout(layout)

            qr_dialog.exec_()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.user_id = None

        layout = QVBoxLayout()

        self.credentials_list = QListWidget()
        self.refresh_credentials()

        self.website_label = QLabel("Website:")
        self.website_input = QLineEdit()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.add_button = QPushButton("Add Credential")
        self.add_button.clicked.connect(self.add_credential)
        self.add_button.setStyleSheet("background-color: #4CAF50; color: white;")

        button_layout = QHBoxLayout()
        self.edit_button = QPushButton("Edit Credential")
        self.edit_button.clicked.connect(self.edit_credential)  # Ensure this line is correct
        self.edit_button.setStyleSheet("background-color: #2196F3; color: white;")

        self.delete_button = QPushButton("Delete Credential")
        self.delete_button.clicked.connect(self.delete_credential)
        self.delete_button.setStyleSheet("background-color: #f44336; color: white;")

        self.view_button = QPushButton("View Password")
        self.view_button.clicked.connect(self.view_password)
        self.view_button.setStyleSheet("background-color: #FFC107; color: black;")

        self.generate_password_button = QPushButton("Generate Password")
        self.generate_password_button.clicked.connect(self.generate_password)
        self.generate_password_button.setStyleSheet("background-color: #9C27B0; color: white;")

        button_layout.addWidget(self.edit_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.view_button)
        button_layout.addWidget(self.generate_password_button)

        layout.addWidget(QLabel("Stored Credentials"))
        layout.addWidget(self.credentials_list)
        layout.addWidget(self.website_label)
        layout.addWidget(self.website_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.add_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def set_user_id(self, user_id):
        self.user_id = user_id
        self.refresh_credentials()

    def refresh_credentials(self):
        self.credentials_list.clear()
        if self.user_id:
            credentials = fetch_credentials(self.user_id)
            for cred in credentials:
                self.credentials_list.addItem(f"{cred[0]} - {cred[1]}")

    def add_credential(self):
        website = self.website_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if website and username and password:
            encrypted_password = password
            insert_credential(self.user_id, website, username, encrypted_password)
            self.refresh_credentials()
            QMessageBox.information(self, "Success", "Credentials added successfully!")
        else:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")

    def edit_credential(self):
        selected_items = self.credentials_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "No credential selected.")
            return

        selected_credential = selected_items[0].text()
        website, username = selected_credential.split(" - ")

        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Credential")
        dialog.setGeometry(100, 100, 300, 200)

        layout = QFormLayout()

        new_website_input = QLineEdit(website)
        new_username_input = QLineEdit(username)
        new_password_input = QLineEdit()
        new_password_input.setEchoMode(QLineEdit.Password)

        layout.addRow("Website:", new_website_input)
        layout.addRow("Username:", new_username_input)
        layout.addRow("Password:", new_password_input)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.Accepted:
            new_website = new_website_input.text()
            new_username = new_username_input.text()
            new_password = new_password_input.text()

            if new_website and new_username and new_password:
                update_credential(self.user_id, website, username, new_website, new_username, new_password)
                self.refresh_credentials()
                QMessageBox.information(self, "Success", "Credential updated successfully!")
            else:
                QMessageBox.warning(self, "Error", "All fields are required.")

    def delete_credential(self):
        selected_items = self.credentials_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "No credential selected.")
            return

        selected_credential = selected_items[0].text()
        website, username = selected_credential.split(" - ")

        delete_credential(self.user_id, website, username)
        self.refresh_credentials()
        QMessageBox.information(self, "Success", "Credential deleted successfully!")

    def view_password(self):
        selected_items = self.credentials_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "No credential selected.")
            return

        selected_credential = selected_items[0].text()
        website, username = selected_credential.split(" - ")

        password = fetch_password(self.user_id, website, username)
        if password:
            QMessageBox.information(self, "Password", f"Password for {username} at {website}: {password}")
        else:
            QMessageBox.warning(self, "Error", "Password not found.")

    def generate_password(self):
        password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(12))
        self.password_input.setText(password)


class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 800, 600)

        create_database()

        self.stacked_widget = QStackedWidget(self)

        self.login_window = LoginWindow(self.stacked_widget)
        self.register_window = RegisterWindow(self.stacked_widget)
        self.main_window = MainWindow()

        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.register_window)
        self.stacked_widget.addWidget(self.main_window)

        self.setCentralWidget(self.stacked_widget)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManagerApp()
    window.show()
    sys.exit(app.exec_())
