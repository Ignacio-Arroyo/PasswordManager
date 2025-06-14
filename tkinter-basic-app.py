# app.py
import tkinter as tk
from tkinter import messagebox, simpledialog
import random
import string
import pyotp
import qrcode
from PIL import Image, ImageTk
from database_operations import (
    create_database, insert_credential, fetch_credentials, fetch_password,
    verify_user, register_user, get_user_id, get_2fa_secret, update_credential, delete_credential
)

def generate_secure_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def show_frame(frame):
    frame.tkraise()

current_user_id = None

def setup_2fa(user_id):
    secret_key = get_2fa_secret(user_id)
    if secret_key:
        totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=f"user_{user_id}@passwordmanager.com", issuer_name="PasswordManager")
        img = qrcode.make(totp_uri)

        # Save the QR code image to a file
        img.save(f"qrcode_user_{user_id}.png")

        # Display the QR code in a new window
        qr_window = tk.Toplevel(app)
        qr_window.title("QR Code for 2FA Setup")

        # Open the image using PIL
        qr_image = Image.open(f"qrcode_user_{user_id}.png")
        qr_photo = ImageTk.PhotoImage(qr_image)

        # Display the image in a label
        qr_label = tk.Label(qr_window, image=qr_photo)
        qr_label.image = qr_photo  # Keep a reference to avoid garbage collection
        qr_label.pack()

        messagebox.showinfo("2FA Setup", "Scan the QR code with your authenticator app.")

def login():
    global current_user_id
    username = username_entry.get()
    password = password_entry.get()

    if verify_user(username, password):
        current_user_id = get_user_id(username)
        token = simpledialog.askstring("Two-Factor Authentication", "Enter your 2FA token:")

        secret_key = get_2fa_secret(current_user_id)
        if secret_key:
            totp = pyotp.TOTP(secret_key)
            if totp.verify(token):
                messagebox.showinfo("Login", "Login Successful!")
                credentials_listbox.delete(0, tk.END)
                credentials = fetch_credentials(current_user_id)
                for cred in credentials:
                    credentials_listbox.insert(tk.END, f"{cred[0]} - {cred[1]}")
                show_frame(main_frame)
            else:
                messagebox.showerror("Login", "Invalid 2FA token.")
        else:
            messagebox.showerror("Login", "2FA not set up for this user.")
    else:
        messagebox.showerror("Login", "Invalid username or password.")

def register():
    username = register_username_entry.get()
    password = register_password_entry.get()

    if username and password:
        secret_key = register_user(username, password)
        if secret_key:
            messagebox.showinfo("Register", "Registration Successful! Please set up 2FA.")
            setup_2fa(get_user_id(username))
            show_frame(login_frame)
        else:
            messagebox.showerror("Register", "Username already exists!")
    else:
        messagebox.showerror("Register", "Please enter both username and password.")

def add_credential():
    website = website_entry.get()
    username = new_username_entry.get()
    password = new_password_entry.get()

    if website and username and password:
        encrypted_password = password
        insert_credential(current_user_id, website, username, encrypted_password)
        credentials_listbox.insert(tk.END, f"{website} - {username}")
        messagebox.showinfo("Success", "Credentials added successfully!")
    else:
        messagebox.showerror("Error", "Please fill in all fields.")

def edit_credential():
    selected_index = credentials_listbox.curselection()
    if not selected_index:
        messagebox.showerror("Error", "No credential selected.")
        return

    selected_credential = credentials_listbox.get(selected_index)
    website, username = selected_credential.split(" - ")

    new_website = simpledialog.askstring("Edit Credential", "Website:", initialvalue=website)
    new_username = simpledialog.askstring("Edit Credential", "Username:", initialvalue=username)
    new_password = simpledialog.askstring("Edit Credential", "Password:", show='*')

    if new_website and new_username and new_password:
        update_credential(current_user_id, website, username, new_website, new_username, new_password)
        credentials_listbox.delete(selected_index)
        credentials_listbox.insert(selected_index, f"{new_website} - {new_username}")
        messagebox.showinfo("Success", "Credential updated successfully!")
    else:
        messagebox.showerror("Error", "All fields are required.")

def handle_delete_credential():
    selected_index = credentials_listbox.curselection()
    if not selected_index:
        messagebox.showerror("Error", "No credential selected.")
        return

    selected_credential = credentials_listbox.get(selected_index)
    website, username = selected_credential.split(" - ")

    delete_credential(current_user_id, website, username)
    credentials_listbox.delete(selected_index)
    messagebox.showinfo("Success", "Credential deleted successfully!")

def view_password():
    selected_index = credentials_listbox.curselection()
    if not selected_index:
        messagebox.showerror("Error", "No credential selected.")
        return

    selected_credential = credentials_listbox.get(selected_index)
    website, username = selected_credential.split(" - ")

    password = fetch_password(current_user_id, website, username)
    if password:
        messagebox.showinfo("Password", f"Password for {username} at {website}: {password}")
    else:
        messagebox.showerror("Error", "Password not found.")

def generate_password():
    password = generate_secure_password()
    new_password_entry.delete(0, tk.END)
    new_password_entry.insert(0, password)

# Create the main application window
app = tk.Tk()
app.title("Password Manager")
app.geometry("600x500")

# Create and set up the database
create_database()

# Create frames for different views
login_frame = tk.Frame(app)
register_frame = tk.Frame(app)
main_frame = tk.Frame(app)

# Place all frames in the same window
for frame in (login_frame, register_frame, main_frame):
    frame.grid(row=0, column=0, sticky='nsew')

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(0, weight=1)

# Login Frame
tk.Label(login_frame, text="Username", font=('Arial', 14)).pack(pady=10)
username_entry = tk.Entry(login_frame, font=('Arial', 14))
username_entry.pack(pady=5, padx=20, fill='x')

tk.Label(login_frame, text="Password", font=('Arial', 14)).pack(pady=10)
password_entry = tk.Entry(login_frame, show="*", font=('Arial', 14))
password_entry.pack(pady=5, padx=20, fill='x')

login_button = tk.Button(login_frame, text="Login", command=login, font=('Arial', 14))
login_button.pack(pady=20)

register_button = tk.Button(login_frame, text="Register", command=lambda: show_frame(register_frame), font=('Arial', 14))
register_button.pack(pady=5)

# Register Frame
tk.Label(register_frame, text="Register Username", font=('Arial', 14)).pack(pady=10)
register_username_entry = tk.Entry(register_frame, font=('Arial', 14))
register_username_entry.pack(pady=5, padx=20, fill='x')

tk.Label(register_frame, text="Register Password", font=('Arial', 14)).pack(pady=10)
register_password_entry = tk.Entry(register_frame, show="*", font=('Arial', 14))
register_password_entry.pack(pady=5, padx=20, fill='x')

register_submit_button = tk.Button(register_frame, text="Register", command=register, font=('Arial', 14))
register_submit_button.pack(pady=20)

# Main Frame
tk.Label(main_frame, text="Stored Credentials", font=('Arial', 14)).pack(pady=10)
credentials_listbox = tk.Listbox(main_frame, font=('Arial', 12), height=5)
credentials_listbox.pack(pady=5, padx=20, fill='both', expand=True)

button_frame = tk.Frame(main_frame)
button_frame.pack(pady=10)

edit_button = tk.Button(button_frame, text="Edit Credential", command=edit_credential, font=('Arial', 12))
edit_button.pack(side=tk.LEFT, padx=5)

delete_button = tk.Button(button_frame, text="Delete Credential", command=handle_delete_credential, font=('Arial', 12))
delete_button.pack(side=tk.LEFT, padx=5)

view_button = tk.Button(button_frame, text="View Password", command=view_password, font=('Arial', 12))
view_button.pack(side=tk.LEFT, padx=5)

generate_password_button = tk.Button(button_frame, text="Generate Password", command=generate_password, font=('Arial', 12))
generate_password_button.pack(side=tk.LEFT, padx=5)

tk.Label(main_frame, text="Website", font=('Arial', 14)).pack(pady=10)
website_entry = tk.Entry(main_frame, font=('Arial', 14))
website_entry.pack(pady=5, padx=20, fill='x')

tk.Label(main_frame, text="Username", font=('Arial', 14)).pack(pady=10)
new_username_entry = tk.Entry(main_frame, font=('Arial', 14))
new_username_entry.pack(pady=5, padx=20, fill='x')

tk.Label(main_frame, text="Password", font=('Arial', 14)).pack(pady=10)
new_password_entry = tk.Entry(main_frame, show="*", font=('Arial', 14))
new_password_entry.pack(pady=5, padx=20, fill='x')

add_button = tk.Button(main_frame, text="Add Credential", command=add_credential, font=('Arial', 14))
add_button.pack(pady=20)

# Show the login frame initially
show_frame(login_frame)

# Run the application
app.mainloop()
