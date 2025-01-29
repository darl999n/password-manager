import hashlib
import tkinter as tk
from tkinter import messagebox
import re
import secrets
import string
import customtkinter as ctk

password_manager = {}

# Styling 
FONT = ("Helvetica", 12)
BUTTON_FONT = ("Helvetica", 12, "bold")
BACKGROUND_COLOR = "#2C3E50"
BUTTON_COLOR = "#3498DB"
BUTTON_HOVER_COLOR = "#2980B9"
ENTRY_COLOR = "#ECF0F1"

# Password strength checker
def check_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong!"

# Password suggestion generator (random strong password)
def suggest_strong_password():
    # Generate a random strong password
    length = 12  # Minimum length of 12
    all_characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = ''.join(secrets.choice(all_characters) for i in range(length))
    return password

# Create account
def create_account():
    username = entry_username.get()
    password = entry_password.get()
    is_strong, message = check_password_strength(password)
    
    if is_strong:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        password_manager[username] = hashed_password
        messagebox.showinfo("Success", "Account created successfully!")
    else:
        messagebox.showerror("Weak Password", message)

# Login
def login():
    username = entry_username.get()
    password = entry_password.get()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if username in password_manager and password_manager[username] == hashed_password:
        messagebox.showinfo("Success", "Login successful!")
    else:
        messagebox.showerror("Error", "Invalid username or password.")


ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")  # Blue color theme

root = ctk.CTk()  # Create a customTkinter window
root.title("My Password Manager")
root.geometry("400x400")  # Set window size

# Create frame for content
frame = ctk.CTkFrame(root, fg_color=BACKGROUND_COLOR)
frame.pack(pady=20, padx=20, expand=True, fill="both")

# Username and Password labels and fields
label_username = ctk.CTkLabel(frame, text="Username:", font=FONT)
label_username.grid(row=0, column=0, pady=10, padx=10)

entry_username = ctk.CTkEntry(frame, font=FONT, placeholder_text="Enter username")
entry_username.grid(row=0, column=1, pady=10, padx=10)

label_password = ctk.CTkLabel(frame, text="Password:", font=FONT)
label_password.grid(row=1, column=0, pady=10, padx=10)

entry_password = ctk.CTkEntry(frame, show="*", font=FONT, placeholder_text="Enter password")
entry_password.grid(row=1, column=1, pady=10, padx=20)

# Create account and login buttons
button_create_account = ctk.CTkButton(frame, text="Create Account", font=BUTTON_FONT, command=create_account)
button_create_account.grid(row=2, column=0, columnspan=2, pady=10, padx=20 )

button_login = ctk.CTkButton(frame, text="Login", font=BUTTON_FONT, command=login)
button_login.grid(row=3, column=0, columnspan=2, pady=10, padx=20)

# Display password suggestion (new password on every session)
suggested_password = suggest_strong_password()
label_suggestion = ctk.CTkLabel(frame, text="Suggested Password: " + suggested_password, font=FONT)
label_suggestion.grid(row=4, column=0, columnspan=2, pady=10, padx=20)


root.mainloop()
