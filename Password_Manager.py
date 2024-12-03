import os
import json
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet  # Importing Fernet for encryption

# Logging configuration
logging.basicConfig(filename='password_manager_audit.log', level=logging.INFO)

# File paths
master_account_file = "master_accounts.json"  # Storing master accounts in JSON
encryption_key_file = "encryption.key"  # Encryption key for password encryption

# Initialize
master_accounts = {}
passwords_storage = {}
reset_tokens = {}

# Load or generate encryption key
def load_or_generate_key():
    if os.path.exists(encryption_key_file):
        with open(encryption_key_file, "rb") as key_file:
            return key_file.read()  # Read existing key
    else:
        # Generate new key and save it to a file
        key = Fernet.generate_key()
        with open(encryption_key_file, "wb") as key_file:
            key_file.write(key)
        return key

# Load encryption key
key = load_or_generate_key()
cipher_suite = Fernet(key)  # Create cipher suite for encryption/decryption

# Function to encrypt a password
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

# Function to decrypt a password
def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Function to save passwords to a JSON file for each master account
def save_passwords(account_email):
    password_file = f"passwords_{account_email}.json"
    with open(password_file, "w") as file:
        json.dump(passwords_storage, file)

# Function to load passwords for a specific master account
def load_passwords(account_email):
    global passwords_storage
    password_file = f"passwords_{account_email}.json"
    if os.path.exists(password_file):
        with open(password_file, "r") as file:
            passwords_storage = json.load(file)
    else:
        passwords_storage = {}


# Function to add a password for an account (store platform, email, and password)
def add_password(account_email, platform, email_account, password):
    encrypted_password = encrypt_password(password)  # Encrypt the password for security

    # Ensure that each master account (account_email) has its own isolated data
    if account_email not in passwords_storage:
        passwords_storage[account_email] = {}

    # Ensure that each platform under the master account (account_email) has its own entry
    if platform not in passwords_storage[account_email]:
        passwords_storage[account_email][platform] = {}

    # Check if the combination of email_account already exists for this platform under the given account_email
    if email_account in passwords_storage[account_email][platform]:
        return f"Error: The account '{email_account}' already exists for platform '{platform}'."

    # Add the new email account and its password under the platform
    passwords_storage[account_email][platform][email_account] = {"email": email_account, "password": encrypted_password}
    
    save_passwords(account_email)  # Save the updated passwords for the account
    logging.info(f"Password added for platform: {platform}, account: {email_account}")
    
    return f"Password for '{platform}' added successfully with email: '{email_account}'!"


# Function to delete a password
def delete_password(account):
    if account in passwords_storage:
        del passwords_storage[account]
        save_passwords(account)
        logging.info(f"Password deleted for account: {account}")
        return f"Password for {account} deleted successfully!"
    else:
        return "Account not found."

# Function to verify master account login
def verify_master_account(account, password):
    if os.path.exists(master_account_file):
        with open(master_account_file, "r") as file:
            stored_accounts = json.load(file)
            stored_password = stored_accounts.get(account)
            if stored_password and password == decrypt_password(stored_password):  # Decrypt password for comparison
                return True
    return False

# Function to create master account
def create_master_account():
    master_email = account_entry.get()
    password = password_entry.get()
    if master_email and password:
        if os.path.exists(master_account_file):
            with open(master_account_file, "r") as file:
                stored_accounts = json.load(file)
        else:
            stored_accounts = {}

        # Check if email already exists
        if master_email and password in stored_accounts:
            messagebox.showerror("Error", "Master account with this email already exists!")
            return  # Stop account creation

        stored_accounts[master_email] = encrypt_password(password)  # Encrypt password before saving

        with open(master_account_file, "w") as file:
            json.dump(stored_accounts, file)

        messagebox.showinfo("Success", "Master account created successfully!")
        show_login_screen()  # Go back to login screen
    else:
        messagebox.showwarning("Error", "Please enter both Gmail account and password.")

# Tkinter GUI for Master Account Login
def show_login_screen():
    def login():
        account = account_entry.get()
        password = password_entry.get()
        if verify_master_account(account, password):
            load_passwords(account)  # Load passwords for the logged-in user
            login_window.destroy()
            show_main_window(account)  # Proceed to main window if login is successful
        else:
            messagebox.showwarning("Login Failed", "Incorrect master account or password.")

    def sign_up():
        login_window.destroy()
        show_sign_up_screen()

    # Create the login window
    global login_window
    login_window = tk.Tk()
    login_window.title("Master Account Login")
    login_window.geometry("300x300")

    ttk.Label(login_window, text="Master Account").pack(pady=10)
    global account_entry
    account_entry = ttk.Entry(login_window, width=30)
    account_entry.pack(pady=5)

    ttk.Label(login_window, text="Password").pack(pady=10)
    global password_entry
    password_entry = ttk.Entry(login_window, width=30, show="*")  # Hidden password entry field
    password_entry.pack(pady=5)

    ttk.Button(login_window, text="Login", command=login).pack(pady=20)
    ttk.Button(login_window, text="Sign Up for New Account", command=sign_up).pack(pady=5)
    
    login_window.mainloop()

# Tkinter GUI for Sign-Up (New User)
def show_sign_up_screen():
    def create_account():
        master_email = account_entry.get()
        password = password_entry.get()
        if master_email and password:
            create_master_account()  # Create the master account
            sign_up_window.destroy()  # Close the sign-up window after account creation
        else:
            messagebox.showwarning("Error", "Please enter both Gmail account and password.")

    def go_back():
        sign_up_window.destroy()  # Close the sign-up window
        show_login_screen()  # Return to the login screen

    # Create the sign-up window
    sign_up_window = tk.Tk()
    sign_up_window.title("Create Master Account")
    sign_up_window.geometry("300x250")

    ttk.Label(sign_up_window, text="Master Gmail Account").pack(pady=10)
    global account_entry
    account_entry = ttk.Entry(sign_up_window, width=30)
    account_entry.pack(pady=5)

    ttk.Label(sign_up_window, text="Password").pack(pady=10)
    global password_entry
    password_entry = ttk.Entry(sign_up_window, width=30, show="*")  # Hidden password entry field
    password_entry.pack(pady=5)

    ttk.Button(sign_up_window, text="Create Account", command=create_account).pack(pady=10)
    ttk.Button(sign_up_window, text="Back to Login", command=go_back).pack(pady=5)  # Back button

    sign_up_window.mainloop()


    # Tkinter GUI for Main Window (after successful login)
import tkinter as tk
from tkinter import ttk, messagebox

# Assuming this is part of the function where the main window is set up
def show_main_window(account_email):
    # Global variables for the entry fields
    global platform_entry, email_account_entry, password_entry

    def handle_add():
        platform = platform_entry.get()  # The platform name (e.g., Gmail, Facebook)
        email_account = email_account_entry.get()  # The email account associated with the platform
        password = password_entry.get()  # The actual password
        
        if platform and email_account and password:
            result = add_password(account_email, platform, email_account, password)
            messagebox.showinfo("Add Password", result)

            # Clear entry fields after adding
            platform_entry.delete(0, tk.END)
            email_account_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Input Error", "All fields must be filled!")
    
    def handle_delete(treeview):
        selected_item = treeview.selection()  # Get the selected row
        if selected_item:
            account = treeview.item(selected_item)['values'][0]  # Get the account name from the selected item
            result = delete_password(account)  # Call the delete function with the account name
            messagebox.showinfo("Delete Password", result)
            treeview.delete(selected_item)  # Remove the item from the Treeview
        else:
            messagebox.showwarning("No Selection", "Please select an account to delete.")

    def view_passwords():
        view_window = tk.Toplevel(main_window)
        view_window.title("View Passwords")
        view_window.geometry("600x400")

        # Create the Treeview widget to display stored passwords
        treeview = ttk.Treeview(view_window, columns=("Platform", "Email", "Password"), show="headings")
        treeview.heading("Platform", text="Platform")
        treeview.heading("Email", text="Email")
        treeview.heading("Password", text="Password")
        treeview.pack(pady=20)

        # Check if the account_email exists in passwords_storage
        if account_email not in passwords_storage:
            messagebox.showerror("Error", f"No data found for account '{account_email}'.")
            return

        # Access the platform data for the given account_email
        for platform, platform_data in passwords_storage[account_email].items():
            # Iterate through the email accounts under this platform
            for email_account, account_data in platform_data.items():
                # Ensure the password exists and can be decrypted
                if "password" in account_data:
                    decrypted_password = decrypt_password(account_data["password"])
                    treeview.insert("", "end", values=(platform, account_data['email'], decrypted_password))
                else:
                    messagebox.showerror("Error", f"No password found for platform '{platform}' under account '{account_email}'.")

        # Add delete button that references treeview
        ttk.Button(view_window, text="Delete Password", command=lambda: handle_delete(treeview)).pack(pady=10)

        # Add close button
        ttk.Button(view_window, text="Close", command=view_window.destroy).pack(pady=20)



    def logout():
        main_window.destroy()  # Close the main window
        show_login_screen()  # Show login screen again

    # Create the main window
    main_window = tk.Tk()
    main_window.title("Password Manager")
    main_window.geometry("600x400")

    # Platform input
    ttk.Label(main_window, text="Platform (e.g., Gmail)").pack(pady=10)
    platform_entry = ttk.Entry(main_window, width=30)  # Define platform entry globally
    platform_entry.pack(pady=5)

    # Email account input
    ttk.Label(main_window, text="Email or Gmail Account").pack(pady=10)
    email_account_entry = ttk.Entry(main_window, width=30)  # Define email account entry globally
    email_account_entry.pack(pady=5)

    # Password input
    ttk.Label(main_window, text="Password").pack(pady=10)
    password_entry = ttk.Entry(main_window, width=30, show="*")  # Define password entry globally
    password_entry.pack(pady=5)

    # Add password button
    ttk.Button(main_window, text="Add Password", command=handle_add).pack(pady=20)

    # View passwords button
    ttk.Button(main_window, text="View Passwords", command=view_passwords).pack(pady=10)
    
    # Logout button
    ttk.Button(main_window, text="Logout", command=logout).pack(pady=10)

    main_window.mainloop()


# Start with the login screen
show_login_screen()

