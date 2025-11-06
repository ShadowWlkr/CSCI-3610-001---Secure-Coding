"""
Flask Application Scaffold: Google OAuth 2.0 Login with JWT and SQLite
---------------------------------------------------------------------
This scaffold defines the structure, routes, and function names for a Flask
application that authenticates users via Google Sign-In, verifies their identity,
issues a JWT, and stores basic user information in an SQLite database.

All implementation details have been omitted for instructional purposes.
"""
# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from flask import Flask, redirect, request, jsonify, session, make_response
import os, sqlite3, jwt, time, requests
from dotenv import load_dotenv
from functools import wraps

# ---------------------------------------------------------------------------
# Flask App Configuration
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:5000/auth/callback"
DATABASE_PATH = "database.db"

# ---------------------------------------------------------------------------
# Database Setup and Helper Functions
# ---------------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)                                                       # Connect to databse
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (                  
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            name TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()                                                                               # Save table                                       
    conn.close()                                                                                # Close table created

def get_db_connection():
    return sqlite3.connect(DATABASE_PATH)                                                       # Return new connection to db

def find_user_by_google_id(google_id):
    conn = get_db_connection()                                                                  # Connect to db
    user = conn.execute("SELECT * FROM users WHERE google_id = ?", (google_id,)).fetchone()     # Look up user w/ "google_id" 
    conn.close()                                                                                # Close connection
    return user                                                                                 # return user if found; else None 

def create_user(google_id, name, email):
    conn = get_db_connection()                                                                  # Connect to db
    cur = conn.execute("INSERT INTO users (google_id, name, email) VALUES (?, ?, ?)",           # Add user to db
                       (google_id, name, email))
    conn.commit()                                                                               # Save user to db
    user_id = cur.lastrowid                                                                     # Get id of new user, used for token later 
    conn.close()                                                                                # Close connection
    return user_id                                                                              # Return id of new user

# ---------------------------------------------------------------------------
# OAuth 2.0 and Authentication Routes
# ---------------------------------------------------------------------------

@app.route("/login")
def login():
    auth_url = (                                                                                # Authentication URl
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"                                                        # Google app’s client ID
        f"&redirect_uri={REDIRECT_URI}"                                                         # URL Google will redirect back to
        "&response_type=code"                                                                   # Expect an authorization code
        "&scope=openid%20email%20profile"                                                       # Request access to user's ID, email, and profile
    )
    return redirect(auth_url)                                                                   # Redirect the user to Google’s login page


@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")                                                             # Get authorization code from Google callback
    if not code:                                                                                # If no code is returned; 
        return jsonify({"error": "Missing authorization code"}), 400                            # Return error

    token_data = {                                                                              # Data to exchange the code for access and ID tokens
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",  
    }

    token_resp = requests.post("https://oauth2.googleapis.com/token", data=token_data).json()   # Request tokens from Google
    id_token = token_resp.get("id_token")                                                       # Extract ID token from response

    if not id_token:                                                                            # If no token;
        return jsonify({"error": "Failed to retrieve ID token"}), 400                           # Return error

    decoded = jwt.decode(id_token, options={"verify_signature": False})                         # Decode ID token
    google_id, name, email = decoded["sub"], decoded.get("name"), decoded.get("email")          # Extract user info from token

    user = find_user_by_google_id(google_id)                                                    # Check if user in db
    user_id = create_user(google_id, name, email) if not user else user[0]                      # Create new user if not found

    token = issue_jwt(user_id, email)                                                           # Generate own JWT token
    return jsonify({"token": token})                                                            # Return token to the client


# ---------------------------------------------------------------------------
# JWT Issuing and Validation
# ---------------------------------------------------------------------------

def issue_jwt(user_id, email):
    payload = {  
        "sub": user_id,                                                                         # Subject – identifies the user
        "email": email,                                                                         # Include user's email
        "exp": int(time.time()) + 3600                                                          # Expires in 1 hour
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")                               # Encode and return JWT using app's secret key

def verify_jwt(token):
    try:
        return jwt.decode(token, app.secret_key, algorithms="HS256")                            # Decode and verify JWT with secret key
    except jwt.ExpiredSignatureError:                                                           # Error if expired
        raise Exception("Token expired")
    except jwt.InvalidTokenError:                                                               # Error if invalid or corrupted
        raise Exception("Invalid token")

def require_auth(f):
    @wraps(f)                                                                                   
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization")                                           # Get the Authorization header from request
        if not header or not header.startswith("Bearer "):                                      # Check if exists and starts with "Bearer "
            return jsonify({"error": "Missing or invalid Authorization header"}), 401           # Reject if missing or malformed
        
        token = header.split(" ")[1]                                                            # Extract the JWT from header
        try:
            request.user = verify_jwt(token)                                                    # Verify token and attach user info to request
        except Exception as e:                                                                  # If verification fails;
            return jsonify({"error": str(e)}), 401                                              # Error with reason
        
        return f(*args, **kwargs)                                                               # If valid, call protected route function
    return wrapper                                                                              # Return fancy gift wrappeer


# ---------------------------------------------------------------------------
# Protected Routes
# ---------------------------------------------------------------------------

@app.route("/profile")                                                                          # This does not work at all idk why, keeps showing error after authentication
@require_auth                                                                                   # Protect this route so only authenticated users can access it
def profile():
    return jsonify({"message": "Authenticated.", "user": request.user})                         # Return confirmation and decoded user info

@app.route("/")
def home():
    return "Welcome to hell! visit /login to authenticate with Google."                         # Home page message


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Initialize database if needed, then start the Flask development server
    init_db()
    app.run(debug=True)

