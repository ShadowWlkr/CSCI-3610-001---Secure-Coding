import sys  
import os
import time
import re
import hmac # Used for secure comparison for password hashes
import hashlib # Used to perform secure hashing (SHA-256 + PBKDF2) for both password protection and device fingerprinting
import getpass # Used to retrieve the current system username, used in fingerprinting the users computer
import socket # Used to get host name of who is running the program, used in fingerprinting
import uuid # Used to get MAC address of the users computer, used in fingerprinting
from datetime import datetime
import winreg # Used to interact with the Windows Registry, to simulate server-side of program
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox

"""
===== Should Resist =====
    - Debuggers       → exits if traced
    - Virtual Machines → fuses VM environments
    - Brute-force     → max attempts + delay + block
    - Reverse Eng.    → PyArmor obfuscation
    - Static Analysis → stripped, UPX packed
    
===== Notes =====
     pyarmor gen Project_0-Secure_Login_Pretest.py --output dist-obf
     pyinstaller Project_0-Secure_Login_Pretest.spec
"""
# ==================== App Config ====================
APP_REG_PATH = r"Software\Project_0-Secure_Login_Pretest" # Custom registry path to isolate data from common locations
USERS_KEY_PATH = APP_REG_PATH + r"\Users" # Used to house the hashed default username and password in register as if in serverside
BLOCKED_USERS_PATH = APP_REG_PATH + r"\Blocked" # Used to house the hashed blocked user info in register as if in serverside

# Session limitations to reduce brute force and time-based attacks
MAX_RUNTIME_SECONDS = 120 # Prevents long-running access attempts (e.g., time-based enumeration)
MAX_ATTEMPTS = 3 # Limits brute force attempts
FAILURE_DELAY_SECONDS = 1.0 # Slow down attackers in how fast they can input their attempts

# Strong password hashing parameters
PBKDF2_ITERATIONS = 200_000 # High iteration count == High computational cost for attackers
HASH_ALG = "sha256" # Type of hashing algorithm used for passwords and fingerprinting 
SALT_LEN = 16 # Length of salt added before hashing valuable data

# Hardcoded credentials
CORRECT_USERNAME = "Mohg, Lord of Blood"
CORRECT_PASSWORD = "IOweUCookoutIGuess!23#" # Not really
DUMMY_HASH_HEX = "c15fcb7fc756ca25f530f150efb659f4422bdbf1aa9ba66794891c540dba0db1"  # Used to mitigate timing attacks when username is invalid

# Prevent common usernames often targeted by bots
FORBIDDEN_USERNAMES = {
    "admin", "root", "administrator", "user", "guest", "test", "info"
}

# ==================== Registry Helpers ====================
def _ensure_key(path: str): # To create key (folder in Registry data) to house all subkeys and values
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) # Get root key, create that key from specified path in registry, 0 for reserved idky, and allow access to write and update values in this key

def reg_write(k, name, value, kind=winreg.REG_SZ): # To write a value into the Windows Registry under an already opened key handle k
    winreg.SetValueEx(k, name, 0, kind, value) # Open registry key, name value, reserve w/ 0, specify type of data (SZ for string + DWORD for int), and the value to store

def reg_read_str(k, name, default=None): # To load values from registry
    try:
        v, _ = winreg.QueryValueEx(k, name)   # Open key, find name of value within
        return str(v)                         # return for later use
    except FileNotFoundError:
        return default

# ==================== Fingerprinting & Blocklist ====================
def get_device_fingerprint(): # Made to create a unique fingerprint/id of the computer using the program, used to block user if failed to login or attempted hacking
    user = getpass.getuser() 
    hostname = socket.gethostname() 
    mac = uuid.getnode()
    fingerprint_str = f"{user}@{hostname}-{mac}" # Combine user, hostname of the machine, and MAC to then 
    return hashlib.sha256(fingerprint_str.encode()).hexdigest() # Be returned as a hashed value to be used in blocking the user if necessary 

def is_user_blocked(): # Made to determine if user accessing program is blocked from accessing by checking Registry value
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, BLOCKED_USERS_PATH, 0, winreg.KEY_READ) # Open registry key using root level given path to the blocked users and ONLY reads the value to k the handle
        try:
            value = reg_read_str(k, get_device_fingerprint()) # Read from blocked list given the fingerprint of computer, see if on list
            return value == "blocked"
        finally:
            winreg.CloseKey(k) # Release handle to registry to prevent mem. leaks
    except FileNotFoundError:
        return False

def block_current_user(): # Made to block user if failed to login, attempted brute force, etc. 
    k = _ensure_key(BLOCKED_USERS_PATH) # Ensure key with blocked users sub key exists
    try:
        reg_write(k, get_device_fingerprint(), "blocked", winreg.REG_SZ) # Write user's fingerprint to registry
    finally:
        winreg.CloseKey(k)

def unblock_current_user(): # Made to unblock user after successful login
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, BLOCKED_USERS_PATH, 0, winreg.KEY_ALL_ACCESS) # Open registry key with read and write permissions and 
        winreg.DeleteValue(k, get_device_fingerprint()) # Remove current users fingerprint from values
        winreg.CloseKey(k)
    except FileNotFoundError:
        pass

# ==================== User Store ====================
USERNAME_RE = re.compile(r"^[\w .,'-]{3,64}$") # Regex used to ensure only valid usernames are allowed, especailly if expanding to more than default user

def validate_username(u: str) -> bool:
    return bool(USERNAME_RE.fullmatch(u.strip())) # Remove any whitespace, and ensures string matches regex

def pbkdf2_hash(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes: # To secure password hash using PBKDF2-HMAC 
    return hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, iterations) # Create hash of password using SHA256, pass in the password encoded by utf-8

def get_user_key(username: str): # To create user subkey if it does not exist already so that the value (fingerprint) can be stored there
    return _ensure_key(USERS_KEY_PATH + fr"\{username}")

def ensure_user_credentials(username: str, plaintext_password: str = None):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, USERS_KEY_PATH + fr"\{username}", 0, winreg.KEY_READ) # Open registry and see if users fingerprint is in the subkey
        winreg.CloseKey(k)
        return
    except FileNotFoundError: # If user is not found, add new user by
        if plaintext_password is None:
            return
        k = get_user_key(username) # Creating new subkey for user
        try:
            salt = os.urandom(SALT_LEN) # Generate pseudo-random salt
            h = pbkdf2_hash(plaintext_password, salt) # And create a hash for the password of the user

            # Write all info needed for the user to be properly stored in the registry
            reg_write(k, "username", username)
            reg_write(k, "salt_hex", salt.hex())
            reg_write(k, "hash_hex", h.hex())
            reg_write(k, "iterations", str(PBKDF2_ITERATIONS))
            reg_write(k, "created_utc", datetime.utcnow().isoformat() + "Z")
        finally:
            winreg.CloseKey(k)

def load_user_record(username: str):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, USERS_KEY_PATH + fr"\{username}", 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    try:
        salt_hex = reg_read_str(k, "salt_hex")
        hash_hex = reg_read_str(k, "hash_hex")
        iterations = int(reg_read_str(k, "iterations", str(PBKDF2_ITERATIONS)))
        return {
            "salt": bytes.fromhex(salt_hex) if salt_hex else None,
            "hash": bytes.fromhex(hash_hex) if hash_hex else None,
            "iterations": iterations
        }
    finally:
        winreg.CloseKey(k)

def verify_user_password(username: str, password: str) -> bool:
    rec = load_user_record(username)
    if not rec or not rec["salt"] or not rec["hash"]:
        _ = hmac.compare_digest(bytes.fromhex(DUMMY_HASH_HEX), bytes.fromhex(DUMMY_HASH_HEX))
        return False
    candidate = hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), rec["salt"], rec["iterations"])
    return hmac.compare_digest(candidate, rec["hash"])

# ==================== Pre-form startup ====================
_ensure_key(APP_REG_PATH)
_ensure_key(USERS_KEY_PATH)
_ensure_key(BLOCKED_USERS_PATH)

if is_user_blocked():
    messagebox.showerror("Access Denied", "You've been blocked from accessing this application.")
    sys.exit(1)

if validate_username(CORRECT_USERNAME):
    try:
        ensure_user_credentials(CORRECT_USERNAME, CORRECT_PASSWORD)
    except Exception:
        pass

# ==================== UI ====================
app = tb.Window(themename="cosmo")
app.title("Login Form")
app.geometry("480x360")
app.resizable(False, False)
app.configure(background="#001f3f")  # Navy blue background

style = tb.Style()
style.configure("TLabel", foreground="#FFD700", background="#001f3f")   # Gold text
style.configure("TEntry", fieldbackground="#f0f0f0", foreground="#000000")  # Keep entries legible
style.configure("TButton", foreground="#001f3f", background="#FFD700")

attempts_left = MAX_ATTEMPTS
remaining_seconds = MAX_RUNTIME_SECONDS
paste_enabled_session = False
login_started = False
login_successful = False

def enable_session_paste(event=None): # Enable paste for the session for ease of testing compared to tpying in a long 25char password
    global paste_enabled_session
    paste_enabled_session = True
    messagebox.showinfo("Paste Enabled", "Paste is now enabled for this session in Username & Password fields.")
app.bind_all("<Control-Alt-p>", enable_session_paste)

def on_close(): # To ensure the user cannot try to brute force and close before being blocked
    if login_started and not login_successful:
        block_current_user()
    app.destroy()
    sys.exit(0)
app.protocol("WM_DELETE_WINDOW", on_close)

def allow_paste_now(widget): return paste_enabled_session and (widget is username_entry or widget is password_entry)
def on_ctrl_c(e): return "break"
def on_ctrl_v(e): return None if allow_paste_now(e.widget) else "break"
def on_ctrl_x(e): return "break"
def on_shift_insert(e): return None if allow_paste_now(e.widget) else "break"
def disable_copy_paste(entry_widget):
    entry_widget.bind("<Button-3>", lambda e: "break")
    entry_widget.bind("<Control-c>", on_ctrl_c)
    entry_widget.bind("<Control-v>", on_ctrl_v)
    entry_widget.bind("<Control-x>", on_ctrl_x)
    entry_widget.bind("<Shift-Insert>", on_shift_insert)

def update_countdown():
    global remaining_seconds
    mins, secs = divmod(max(remaining_seconds, 0), 60)
    countdown_label.config(text=f"Time left: {mins:02d}:{secs:02d}")
    if remaining_seconds <= 0:
        messagebox.showerror("Session Timeout", "Time expired. Program will close.")
        app.destroy()
        sys.exit(0)
    else:
        remaining_seconds -= 1
        app.after(1000, update_countdown)

def attempt_login():
    global attempts_left, login_started, login_successful
    login_started = True

    u = username_entry.get()
    p = password_entry.get()

    if u.strip().lower() in FORBIDDEN_USERNAMES:
        block_current_user()
        messagebox.showerror("Nope", "Really? Do I look that dumb... I am, but still.")
        app.destroy()
        sys.exit(0)

    if not validate_username(u):
        attempts_left -= 1
        time.sleep(FAILURE_DELAY_SECONDS)
        if attempts_left > 0:
            messagebox.showerror("Login Failed", f"Invalid login.\nAttempts left: {attempts_left}")
        else:
            block_current_user()
            messagebox.showerror("Locked Out", "Too many failed attempts.\nProgram will close.")
            app.destroy()
            sys.exit(0)
        return

    if u.strip() == CORRECT_USERNAME:
        password_ok = verify_user_password(u.strip(), p)
    else:
        _ = hmac.compare_digest(bytes.fromhex(DUMMY_HASH_HEX), bytes.fromhex(DUMMY_HASH_HEX))
        password_ok = False

    if password_ok:
        login_successful = True
        unblock_current_user()
        messagebox.showinfo("Login Successful", "You are successfully logged into the system.\n\"Congrats YOUR in -Jake 2025\"")
        app.destroy()
        sys.exit(0)
    else:
        attempts_left -= 1
        time.sleep(FAILURE_DELAY_SECONDS)
        if attempts_left > 0:
            messagebox.showerror("Login Failed", f"Invalid login.\nAttempts left: {attempts_left}")
        else:
            block_current_user()
            messagebox.showerror("Locked Out", "Too many failed attempts.\nProgram will close.")
            app.destroy()
            sys.exit(0)

title_label = tb.Label(app, text="Welcome to Hell! Good Luck!", font=("Helvetica", 18, "bold"))
title_label.pack(pady=(10, 6))

countdown_label = tb.Label(app, text="", font=("Consolas", 11, "bold"))
countdown_label.pack(anchor="nw", padx=10, pady=(4, 0))

username_label = tb.Label(app, text="Username:")
username_label.pack(pady=(10, 0))
username_entry = tb.Entry(app, width=38)
username_entry.pack()

password_label = tb.Label(app, text="Password:")
password_label.pack(pady=(10, 0))
pw_row = tb.Frame(app)
pw_row.pack()
password_entry = tb.Entry(pw_row, width=38, show="*")
password_entry.pack(side="left")

disable_copy_paste(username_entry)
disable_copy_paste(password_entry)

login_button = tb.Button(app, text="Login", bootstyle="primary", command=attempt_login)
login_button.pack(pady=16)

update_countdown()
app.mainloop()




