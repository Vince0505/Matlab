import sqlite3
from tkinter import ttk, messagebox
from tkinter import *
from PIL import Image, ImageTk
import bcrypt

# Connect to SQLite database
conn = sqlite3.connect('publication_repository.db')
cursor = conn.cursor()

# Create users table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT
                )''')

conn.commit()

# Function to add a new user
def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute('''INSERT INTO users (username, password) VALUES (?, ?)''', (username, hashed_password))
    conn.commit()

# Function to authenticate users
def authenticate(username, password):
    cursor.execute('''SELECT * FROM users WHERE username = ?''', (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return True
    else:
        return False

# Function to handle sign-up button click
def sign_up():
    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()

    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
    elif len(password) < 8:
        messagebox.showerror("Error", "Password must be at least 8 characters long.")
    else:
        add_user(username, password)
        messagebox.showinfo("Success", "User created successfully.")

# Function to handle sign-in button click
def sign_in():
    username = login_username_entry.get()
    password = login_password_entry.get()

    if authenticate(username, password):
        open_main_window(username)
    else:
        messagebox.showerror("Error", "Invalid username or password.")

# Function to open the main window
def open_main_window(username):
    root.withdraw()  # Hide the sign-in window

    main_window = Toplevel(root)
    main_window.title("Academic Research Publication Repository")
    main_window.geometry("800x600")

    # Welcome message
    welcome_label = ttk.Label(main_window, text=f"Welcome, {username}!", font=("Helvetica", 16))
    welcome_label.pack(pady=10)

    # Create a frame for publication submission form
    submission_frame = ttk.Frame(main_window, padding="10 10 10 10")
    submission_frame.place(relx=0.5, rely=0.5, anchor="center")

    # Title label and entry
    title_label = ttk.Label(submission_frame, text="Title:")
    title_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

    title_entry = ttk.Entry(submission_frame, width=40)
    title_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

    # Author label and entry
    author_label = ttk.Label(submission_frame, text="Author:")
    author_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")

    author_entry = ttk.Entry(submission_frame, width=40)
    author_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

    # Category label and entry
    category_label = ttk.Label(submission_frame, text="Category:")
    category_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")

    category_entry = ttk.Entry(submission_frame, width=40)
    category_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

    # Content label and text area
    content_label = ttk.Label(submission_frame, text="Content:")
    content_label.grid(row=3, column=0, padx=10, pady=5, sticky="ne")

    content_text = Text(submission_frame, width=40, height=10)
    content_text.grid(row=3, column=1, padx=10, pady=5, sticky="w")

    # Image Path label and entry
    image_path_label = ttk.Label(submission_frame, text="Image Path:")
    image_path_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")

    image_path_entry = ttk.Entry(submission_frame, width=40)
    image_path_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

    # Function to add a publication to the database
    def add_publication(title, author, category, content, image_path, user_id):
        cursor.execute('''INSERT INTO publications (title, author, category, content, image_path, user_id)
                          VALUES (?, ?, ?, ?, ?, ?)''', (title, author, category, content, image_path, user_id))
        conn.commit()
        messagebox.showinfo("Success", "Publication added successfully.")

    # Function to handle publication submission
    def submit_publication():
        title = title_entry.get()
        author = author_entry.get()
        category = category_entry.get()
        content = content_text.get("1.0", END)
        image_path = image_path_entry.get()
        # Assuming user_id is passed from the sign-in process or retrieved from the database
        user_id = 1  # Replace with appropriate user_id
        add_publication(title, author, category, content, image_path, user_id)

    # Submit button
    submit_button = ttk.Button(submission_frame, text="Submit", command=submit_publication)
    submit_button.grid(row=5, columnspan=2, padx=10, pady=10)

    main_window.mainloop()

# Tkinter GUI code for sign-up
root = Tk()
root.title("Sign Up / Sign In")
root.geometry("400x400")

# Notebook for switching between sign-up and sign-in
notebook = ttk.Notebook(root)
notebook.pack(expand=1, fill='both')

# Create a frame for sign-up form
signup_frame = ttk.Frame(notebook, padding="10 10 10 10")
signup_frame.pack(fill='both', expand=True)

# Create a frame for sign-in form
signin_frame = ttk.Frame(notebook, padding="10 10 10 10")
signin_frame.pack(fill='both', expand=True)

notebook.add(signup_frame, text="Sign Up")
notebook.add(signin_frame, text="Sign In")

# Username label and entry for sign-up
username_label = ttk.Label(signup_frame, text="Username:")
username_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

username_entry = ttk.Entry(signup_frame, width=30)
username_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

# Password label and entry for sign-up
password_label = ttk.Label(signup_frame, text="Password:")
password_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")

password_entry = ttk.Entry(signup_frame, show="*", width=30)
password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

# Confirm Password label and entry for sign-up
confirm_password_label = ttk.Label(signup_frame, text="Confirm Password:")
confirm_password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")

confirm_password_entry = ttk.Entry(signup_frame, show="*", width=30)
confirm_password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

# Sign-up button
signup_button = ttk.Button(signup_frame, text="Sign Up", command=sign_up)
signup_button.grid(row=3, columnspan=2, padx=10, pady=10)

# Username label and entry for sign-in
login_username_label = ttk.Label(signin_frame, text="Username:")
login_username_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

login_username_entry = ttk.Entry(signin_frame, width=30)
login_username_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

# Password label and entry for sign-in
login_password_label = ttk.Label(signin_frame, text="Password:")
login_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")

login_password_entry = ttk.Entry(signin_frame, show="*", width=30)
login_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

# Sign-in button
signin_button = ttk.Button(signin_frame, text="Sign In", command=sign_in)
signin_button.grid(row=2, columnspan=2, padx=10, pady=10)

root.mainloop()