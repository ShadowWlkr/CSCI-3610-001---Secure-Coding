import sys  
import os
import time
import re
import hmac # Used for secure comparison for password hashes
import hashlib # Used to perform secure hashing (SHA-256 + PBKDF2) for both password protection and device fingerprinting
import getpass # Used to retrieve the current system username, used in fingerprinting the user's computer
import socket # Used to get host name of who is running the program, used in fingerprinting
import uuid # Used to get MAC address of the user's computer, used in fingerprinting
from datetime import datetime
import winreg # Used to interact with the Windows Registry, to simulate server-side of program
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox

"""
===== Should Resist =====
    - Debuggers       → exits if traced
    - Virtual Machines → refuses VM environments
    - Brute-force     → max attempts + delay + block
    - Reverse Eng.    → PyArmor obfuscation
    - Static Analysis → stripped, UPX packed
    
===== Notes =====
     pyarmor gen Project_0-Secure_Login_Pretest.py --output dist-obf
     pyinstaller Project_0-Secure_Login_Pretest.spec
"""
# ==================== App Config ====================
APP_REG_PATH = r"Software\Project_0-Secure_Login_Pretest" # Custom registry path to isolate data from common locations
USERS_KEY_PATH = APP_REG_PATH + r"\Users" # Used to house the hashed default username and password in registry as if on server-side
BLOCKED_USERS_PATH = APP_REG_PATH + r"\Blocked" # Used to house the hashed blocked user info in registry as if on server-side

# Session limitations to reduce brute force and time-based attacks
MAX_RUNTIME_SECONDS = 120 # Prevents long-running access attempts (e.g., time-based enumeration)
MAX_ATTEMPTS = 3 # Limits brute force attempts
FAILURE_DELAY_SECONDS = 1.0 # Slows down attackers in how fast they can input their attempts

# Strong password hashing parameters
PBKDF2_ITERATIONS = 200_000 # High iteration count == High computational cost for attackers
HASH_ALG = "sha256" # Type of hashing algorithm used for passwords and fingerprinting 
SALT_LEN = 16 # Length of salt added before hashing valuable data

# Hardcoded credentials
CORRECT_USERNAME = "Mohg, Lord of Blood" # Who doesn't like Elden Ring, at least the boss names
CORRECT_PASSWORD = "IOweUCookoutIGuess!23#" # Not really
DUMMY_HASH_HEX = "c15fcb7fc756ca25f530f150efb659f4422bdbf1aa9ba66794891c540dba0db1"  # Used to mitigate timing attacks when username is invalid

# Prevent common usernames often targeted by bots
FORBIDDEN_USERNAMES = {
    "admin", "root", "administrator", "user", "guest", "test", "info"
}

# ==================== Registry Helpers ====================
def _ensure_key(path: str): # To create key (folder in Registry data) to house all subkeys and values
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) # Get root key, create that key from specified path in registry, 0 for reserved, and allow access to write and update values in this key

def reg_write(k, name, value, kind=winreg.REG_SZ): # To write a value into the Windows Registry under an already opened key handle k
    winreg.SetValueEx(k, name, 0, kind, value) # Open registry key, name value, reserve w/ 0, specify type of data (SZ for string or DWORD for int), and the value to store

def reg_read_str(k, name, default=None): # To load values from registry
    try:
        v, _ = winreg.QueryValueEx(k, name)   # Open key, find name of value within
        return str(v)                         # Return for later use
    except FileNotFoundError:
        return default

# ==================== Fingerprinting & Blocklist ====================
def get_device_fingerprint(): # Creates a unique fingerprint/ID of the computer using the program, used to block user if login fails or hacking is attempted
    user = getpass.getuser() 
    hostname = socket.gethostname() 
    mac = uuid.getnode()
    fingerprint_str = f"{user}@{hostname}-{mac}" # Combine user, hostname of the machine, and MAC address
    return hashlib.sha256(fingerprint_str.encode()).hexdigest() # Return as a hashed value to be used in blocking the user if necessary 

def is_user_blocked(): # Determines if user accessing program is blocked from access by checking Registry value
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, BLOCKED_USERS_PATH, 0, winreg.KEY_READ) # Open registry key using root-level given path to blocked users and ONLY read value into handle k
        try:
            value = reg_read_str(k, get_device_fingerprint()) # Read from blocked list given the fingerprint of computer, see if on list
            return value == "blocked"
        finally:
            winreg.CloseKey(k) # Release handle to registry to prevent memory leaks
    except FileNotFoundError:
        return False

def block_current_user(): # Blocks user if login fails, brute force attempted, etc. 
    k = _ensure_key(BLOCKED_USERS_PATH) # Ensure key with blocked users subkey exists
    try:
        reg_write(k, get_device_fingerprint(), "blocked", winreg.REG_SZ) # Write user's fingerprint to registry
    finally:
        winreg.CloseKey(k)

def unblock_current_user(): # Unblocks user after successful login
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, BLOCKED_USERS_PATH, 0, winreg.KEY_ALL_ACCESS) # Open registry key with read and write permissions 
        winreg.DeleteValue(k, get_device_fingerprint()) # Remove current user's fingerprint from values
        winreg.CloseKey(k)
    except FileNotFoundError:
        pass

# ==================== User Store ====================
USERNAME_RE = re.compile(r"^[\w .,'-]{3,64}$") # Regex used to ensure only valid usernames are allowed, especially if expanding to more than default user

def validate_username(u: str) -> bool:
    return bool(USERNAME_RE.fullmatch(u.strip())) # Remove any whitespace, and ensure string matches regex

def pbkdf2_hash(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes: # Secure password hash using PBKDF2-HMAC 
    return hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), salt, iterations) # Create hash of password using SHA256, pass in the password encoded by UTF-8

def get_user_key(username: str): # To create user subkey if it does not exist already so that the value (fingerprint) can be stored there
    return _ensure_key(USERS_KEY_PATH + fr"\{username}")

def ensure_user_credentials(username: str, plaintext_password: str = None): # Ensures user has a subkey in registry to hold values, else create one
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, USERS_KEY_PATH + fr"\{username}", 0, winreg.KEY_READ) # Open registry and see if user's fingerprint is in the subkey
        winreg.CloseKey(k)
        return
    except FileNotFoundError: # If user is not found, add new user
        if plaintext_password is None:
            return
        k = get_user_key(username) # Create new subkey for user
        try:
            salt = os.urandom(SALT_LEN) # Generate pseudo-random salt
            h = pbkdf2_hash(plaintext_password, salt) # Create a hash for the password of the user

            # Write all info needed for the user to be properly stored in the registry
            reg_write(k, "username", username)
            reg_write(k, "salt_hex", salt.hex())
            reg_write(k, "hash_hex", h.hex())
            reg_write(k, "iterations", str(PBKDF2_ITERATIONS))
            reg_write(k, "created_utc", datetime.utcnow().isoformat() + "Z")
        finally:
            winreg.CloseKey(k)

def load_user_record(username: str): # Load all values of user to local variables in program for ease of use
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, USERS_KEY_PATH + fr"\{username}", 0, winreg.KEY_READ) # Create handle to be used for values in subkey
    except FileNotFoundError:
        return None
    try:
        salt_hex = reg_read_str(k, "salt_hex")
        hash_hex = reg_read_str(k, "hash_hex")
        iterations = int(reg_read_str(k, "iterations", str(PBKDF2_ITERATIONS)))
        return { # Return hex into bytes for hashing
            "salt": bytes.fromhex(salt_hex) if salt_hex else None,
            "hash": bytes.fromhex(hash_hex) if hash_hex else None,
            "iterations": iterations
        }
    finally:
        winreg.CloseKey(k)

def verify_user_password(username: str, password: str) -> bool: # Checks if password given matches stored credentials by rehashing it
    rec = load_user_record(username) # Load user info
    if not rec or not rec["salt"] or not rec["hash"]: # If info is incomplete, then there is not enough data to compare to
        _ = hmac.compare_digest(bytes.fromhex(DUMMY_HASH_HEX), bytes.fromhex(DUMMY_HASH_HEX)) # Compare dummy hash to itself to prevent timing attack
        return False
    candidate = hashlib.pbkdf2_hmac(HASH_ALG, password.encode("utf-8"), rec["salt"], rec["iterations"]) # Hash and salt the entered password the same as the stored one
    return hmac.compare_digest(candidate, rec["hash"]) # Use hmac to return a == b to prevent timing analysis

# ==================== Pre-form startup ====================
_ensure_key(APP_REG_PATH) # Create main registry key
_ensure_key(USERS_KEY_PATH) # Create subkey for users
_ensure_key(BLOCKED_USERS_PATH) # Create subkey for blocked users

if is_user_blocked(): # Deny access if user is blocked
    messagebox.showerror("Access Denied", "You've been blocked from accessing this application.")
    sys.exit(1)

if validate_username(CORRECT_USERNAME): # Ensure default username and password are valid
    try:
        ensure_user_credentials(CORRECT_USERNAME, CORRECT_PASSWORD)
    except Exception:
        pass

# ==================== UI ====================
# ChatGPT helped declare app since I was unsure how to work ttkbootstrap
app = tb.Window(themename="cosmo")
app.title("Login Form")
app.geometry("480x360")
app.resizable(False, False)
app.configure(background="#001f3f")  # Navy blue background

# ChatGPT helped me fix the style to ETSU blue and gold
style = tb.Style()
style.configure("TLabel", foreground="#FFD700", background="#001f3f")   # Gold text
style.configure("TEntry", fieldbackground="#f0f0f0", foreground="#000000")  # Keep entries legible
style.configure("TButton", foreground="#001f3f", background="#FFD700")

attempts_left = MAX_ATTEMPTS
remaining_seconds = MAX_RUNTIME_SECONDS
paste_enabled_session = False # Disabled pasting to ensure only typed usernames and passwords are allowed, raising computational costs
login_started = False # Used to see if user has attempted to login, signifying if it was an accidental run or purposeful run to gain entry ethically or unethically
login_successful = False # Used to unblock user after they have attempted to start logging in

def enable_session_paste(event=None): # Enable paste for the session for ease of testing compared to typing in a long 25-character password
    global paste_enabled_session
    paste_enabled_session = True
    messagebox.showinfo("Paste Enabled", "Paste is now enabled for this session in Username & Password fields.")
app.bind_all("<Control-Alt-p>", enable_session_paste) # ChatGPT helped me figure out a command that would be reasonable for this type of function

def on_close(): # Ensure the user cannot try brute force and close before being blocked
    if login_started and not login_successful:
        block_current_user()
    app.destroy()
    sys.exit(0)
app.protocol("WM_DELETE_WINDOW", on_close)

def allow_paste_now(widget): return paste_enabled_session and (widget is username_entry or widget is password_entry) # Used to check if pasting is allowed in the session using the command

# Short methods to block paste with common shortcuts
def on_ctrl_c(e): return "break" 
def on_ctrl_v(e): return None if allow_paste_now(e.widget) else "break"
def on_ctrl_x(e): return "break"
def on_shift_insert(e): return None if allow_paste_now(e.widget) else "break"
def disable_copy_paste(entry_widget): # Main method to fully disable paste using short methods
    entry_widget.bind("<Button-3>", lambda e: "break")
    entry_widget.bind("<Control-c>", on_ctrl_c)
    entry_widget.bind("<Control-v>", on_ctrl_v)
    entry_widget.bind("<Control-x>", on_ctrl_x)
    entry_widget.bind("<Shift-Insert>", on_shift_insert)

def update_countdown():
    global remaining_seconds
    mins, secs = divmod(max(remaining_seconds, 0), 60) # Convert seconds to minutes by splitting remaining seconds
    countdown_label.config(text=f"Time left: {mins:02d}:{secs:02d}") 
    if remaining_seconds <= 0: # End session if user took too long, could potentially block user anyway for taking too long as they may be trying to run a debugger if they bypassed anti-debug policy
        messagebox.showerror("Session Timeout", "Time expired. Program will close.")
        app.destroy()
        sys.exit(0)
    else:
        remaining_seconds -= 1
        app.after(1000, update_countdown)

def attempt_login(): # Where the login magic happens
    global attempts_left, login_started, login_successful # Global login relevant variables so changes persist across program
    login_started = True # User attempted login

    u = username_entry.get()
    p = password_entry.get()

    if u.strip().lower() in FORBIDDEN_USERNAMES: # If user attempts to do the unthinkable, stop program and block user 
        block_current_user()
        messagebox.showerror("Nope", "Really? Do I look that dumb... I am, but still.") # LOL
        app.destroy()
        sys.exit(0)

    if not validate_username(u): # If username entered was invalid
        attempts_left -= 1
        time.sleep(FAILURE_DELAY_SECONDS) # Delay to prevent timing attacks
        if attempts_left > 0:
            messagebox.showerror("Login Failed", f"Invalid login.\nAttempts left: {attempts_left}")
        else:
            block_current_user()
            messagebox.showerror("Locked Out", "Too many failed attempts.\nProgram will close.")
            app.destroy()
            sys.exit(0)
        return

    if u.strip() == CORRECT_USERNAME: # If username is correct, check password
        password_ok = verify_user_password(u.strip(), p)
    else:
        _ = hmac.compare_digest(bytes.fromhex(DUMMY_HASH_HEX), bytes.fromhex(DUMMY_HASH_HEX)) # Compare dummy hash to itself to prevent timing attack
        password_ok = False

    if password_ok:
        login_successful = True
        unblock_current_user() # Unblock user from registry to allow additional login attempts later
        messagebox.showinfo("Login Successful", "You are successfully logged into the system.\n\"Congrats YOU'RE in -Jake 2025\"")
        app.destroy()
        sys.exit(0)
    else: # Failed login case
        attempts_left -= 1
        time.sleep(FAILURE_DELAY_SECONDS)
        if attempts_left > 0:
            messagebox.showerror("Login Failed", f"Invalid login.\nAttempts left: {attempts_left}")
        else:
            block_current_user()
            messagebox.showerror("Locked Out", "Too many failed attempts.\nProgram will close.")
            app.destroy()
            sys.exit(0)
            
# ChatGPT helped fix layout and design of GUI
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
### End of ChatGPT help with GUI ###

disable_copy_paste(username_entry) # Disable paste for username for session
disable_copy_paste(password_entry) # Disable paste for password for session

login_button = tb.Button(app, text="Login", bootstyle="primary", command=attempt_login)
login_button.pack(pady=16)

update_countdown() # Begin countdown
app.mainloop()     # Run app