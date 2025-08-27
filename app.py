import os
import time
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, session, Response
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from modules.db import get_connection
from forms.signup_form import SignupForm
from forms.login_form import LoginForm
from modules.security import hash_password, verify_password



#email service 
# from email_service import send_email  # tera existing file

# AI Dependencies

# Email dependencies
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Google OAuth
from authlib.integrations.flask_client import OAuth

# Cryptography & utilities
import secrets
from dotenv import load_dotenv

# ---------------- LOAD SECRETS ----------------
load_dotenv("secrets.env")  # Load .env or secrets.env file
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "super_secret_key")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ---------------- INIT APP ----------------
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = SECRET_KEY

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"])

# OpenAI client


# ---------------- LOGIN MANAGER ----------------
class User(UserMixin):
    def __init__(self, _id, name, email):
        self.id = str(_id)
        self.name = name
        self.email = email

login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    con = get_connection()
    with con.cursor() as cur:
        cur.execute("SELECT id, name, email FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    if row:
        return User(row["id"], row["name"], row["email"])
    return None

# ---------------- GOOGLE OAUTH ----------------
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("auth_google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    token = google.authorize_access_token()
    user_info = google.userinfo()
    
    if not user_info:
        flash("Google login failed", "danger")
        return redirect(url_for("login"))

    email = user_info.get("email")
    name = user_info.get("name")

    con = get_connection()
    with con.cursor() as cur:
        cur.execute("SELECT id, name, email FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO users (name, email, password_hash, gender) VALUES (%s,%s,%s,%s)",
                (name, email, None, "Not Specified")
            )
            cur.execute("SELECT id, name, email FROM users WHERE email=%s", (email,))
            row = cur.fetchone()

    user = User(row["id"], row["name"], row["email"])
    login_user(user)
    flash("Logged in with Google!", "success")
    return redirect(url_for("profile"))

# ---------------- AI CHAT FREE BOT ROUTE (streaming & fallback) ----------------
@app.route("/crypto-chat", methods=["POST"])
def crypto_chat():
    user_msg = request.json.get("message", "").lower().strip()

    crypto_fallbacks = {
        "which key i keep in caeser cipher and xor cipher": "For Caesar Cipher, the key should be a number between 1 and 25. Using 0 or 26 has no effect, and larger numbers just wrap around. Choose a random number within this range for better security and avoid common shifts like 3. For XOR Cipher, the key should be a random string of characters at least as long as the message you want to encrypt. A longer, truly random key provides better security. Never reuse the same key for different messages, as this can compromise security. Always keep your keys secret and secure! 🔑"
         ,
        "aes": "AES is symmetric encryption. Use 128, 192, or 256-bit keys 🔑",
        "rsa": "RSA is asymmetric. Public/private keys differ. Use 2048-bit or higher 🔐",
        "hash": "Hashing is one-way. SHA-256 or SHA-512 is common 🛡️",
        "key": "Use random, strong keys. Never reuse keys across systems 🔑",
        "cybersecurity": "Always enable 2FA, use strong passwords, and stay updated 🔒",
        "crypto tip": "Keep your crypto private keys safe and backup securely 💡",
        "general knowledge": "Crypto changes fast! Keep learning from trusted sources 📚",
         "hello": "Hello there! 🤖 How can I help you with crypto today?",
         "crypto": "Crypto is digital currency using cryptography for security. Popular ones include Bitcoin and Ethereum 💰",
         "des": "DES is obsolete due to 56-bit keys; avoid in new systems ⚠️",
"3des": "Triple DES improves DES but is deprecated; migrate to AES ⛔",
"blowfish": "Blowfish is a fast block cipher; replaced by modern options like AES",
"twofish": "Twofish is a 128-bit block cipher; secure but less common today",
"serpent": "Serpent was an AES finalist; conservative and secure",
"chacha20": "ChaCha20 is a fast stream cipher; great on mobile/CPU-only 📱",
"salsa20": "Salsa20 is ChaCha’s predecessor; still secure and efficient",
"rsa": "RSA provides public-key encryption/signing; use OAEP/PSS 🔐",
"rsa-2048": "RSA-2048 is baseline secure; good for most current uses",
"rsa-4096": "RSA-4096 adds margin but is slower; keys/certs get heavy",
"ecc": "Elliptic-curve crypto offers strong security with small keys ✨",
"ecdsa": "ECDSA is an ECC signature scheme; use curves like P-256/edwards",
"ed25519": "Ed25519 is a modern, fast, safe signature algorithm ✅",
"x25519": "X25519 is used for key agreement (Diffie-Hellman over Curve25519)",
"diffie-hellman": "DH securely agrees on a shared key over insecure channels 🤝",
"elgamal": "ElGamal is a probabilistic public-key scheme; mostly historical",
"paillier": "Paillier supports additive homomorphism; used in secure compute",
"homomorphic encryption": "Encrypt and compute on data without decrypting 🧮🔒",
"lattice-based crypto": "Lattice schemes underpin many post-quantum systems 🧱",
"post-quantum cryptography": "Crypto designed to resist quantum attacks 🧪",
"kyber": "Kyber is a PQC KEM candidate standardized for key exchange",
"dilithium": "Dilithium is a PQC signature scheme standardized by NIST",
"sphincs+": "SPHINCS+ is a stateless hash-based PQC signature scheme",
"sha-1": "SHA-1 is broken for collisions; do not use 🚫",
"sha-256": "SHA-256 is widely used and trusted for hashing 🛡️",
"sha-512": "SHA-512 is like SHA-256 with 64-bit ops; very robust",
"sha-3": "SHA-3 (Keccak) is a sponge-based hash; secure alternative",
"blake2": "BLAKE2 is fast and secure; great for checksums/hashing",
"blake3": "BLAKE3 is parallel, very fast, and secure for hashing ⚡",
"md5": "MD5 is broken; never use for security purposes ❌",
"ripemd160": "RIPEMD-160 appears secure; used in Bitcoin addresses",
"bcrypt": "bcrypt is a password hashing KDF; slow by design 🔐",
"scrypt": "scrypt is memory-hard KDF; resists GPU attacks",
"argon2": "Argon2id is the recommended modern password hash 🧱",
"hkdf": "HKDF expands/derives keys from initial keying material",
"pbkdf2": "PBKDF2 is legacy KDF; use high iterations if required",
"hmac": "HMAC provides message authentication using a secret key",
"mac": "MAC verifies integrity and authenticity of messages",
"cmac": "CMAC is a block-cipher based MAC; alternative to HMAC",
"gcm": "GCM provides AES encryption + authentication (AEAD) ✅",
"cbc": "CBC mode needs random IV and padding; avoid without MAC",
"cfb": "CFB turns a block cipher into a stream; rarely used now",
"ofb": "OFB is a stream mode; avoid in new designs",
"ctr": "CTR mode is fast but needs unique nonces; pair with MAC",
"xchacha20-poly1305": "XChaCha20-Poly1305 is fast, nonce-tolerant AEAD 🌪️",
"aead": "AEAD modes encrypt and authenticate together—use these 👍",
"nonce": "A unique per-message number; never reuse with same key",
"initialization vector": "IV randomizes encryption; must be unique/unpredictable",
"salt": "Salt prevents rainbow tables; unique per password 🧂",
"key derivation": "Process to derive strong keys from weak secrets",
"key stretching": "Makes passwords costlier to brute force via KDFs",
"key rotation": "Regularly replace keys to limit compromise impact 🔁",
"key management": "Policies, storage, rotation, and access of keys 🔑",
"kms": "Key Management Service centralizes key storage and policies",
"pkcs#7 padding": "Padding scheme used with block ciphers like CBC",
"pkcs#1": "RSA standard defining OAEP and PSS schemes",
"x.509": "Standard for public key certificates used on the web",
"certificate": "Binds a public key to an identity; signed by a CA",
"csr": "Certificate Signing Request sent to a CA for a cert",
"crl": "Certificate Revocation List—revoked certs listing",
"ocsp": "Online Certificate Status Protocol—live revocation check",
"pki": "Public Key Infrastructure—CAs, certs, and policies",
"tls": "Transport Layer Security for secure network channels 🔐",
"ssl": "SSL is old TLS; avoid SSLv2/v3—use TLS 1.2+",
"https": "HTTP over TLS for web security—look for the lock 🔒",
"vpn": "Encrypted tunnel for private network access remotely",
"tor": "Network that anonymizes traffic via onion routing 🧅",
"firewall": "Filters traffic per rules to protect networks",
"ids": "Intrusion Detection System—detects suspicious activity",
"ips": "Intrusion Prevention System—blocks malicious traffic",
"waf": "Web Application Firewall—protects web apps from OWASP risks",
"2fa": "Two-factor auth adds a second proof of identity ✌️",
"mfa": "Multi-factor auth uses 2+ factors: something you know/have/are",
"otp": "One-time password—valid for a single login or window",
"totp": "Time-based OTP—codes change every 30 seconds ⏱️",
"hotp": "HMAC-based OTP—counter driven one-time codes",
"yubikey": "Hardware security key for phishing-resistant login 🔐",
"passkey": "FIDO-based passwordless login; syncs across devices",
"webauthn": "Standard API for strong, phishing-resistant authentication",
"owasp top 10": "Common web risks (SQLi, XSS, etc.); must-know list",
"csrf": "Cross-Site Request Forgery—use tokens, same-site cookies",
"xss": "Cross-Site Scripting—escape output, use CSP 🧯",
"sqli": "SQL Injection—use prepared statements/ORM ✅",
"rce": "Remote Code Execution—strict input validation & sandboxing",
"lfi": "Local File Inclusion—validate paths, disable dynamic includes",
"rfi": "Remote File Inclusion—block external includes; whitelist only",
"ssrf": "Server-Side Request Forgery—restrict egress & metadata access",
"clickjacking": "Use X-Frame-Options/Frame-Ancestors to prevent UI redress",
"rate limiting": "Throttle requests to stop abuse and brute force ⏳",
"brute force": "Many guesses to crack a secret—use MFA, lockouts",
"dictionary attack": "Guess from common lists—strong passwords beat this",
"rainbow table": "Precomputed hash tables—salts defeat them 🧂",
"pepper": "Server-side secret added before hashing—store separately",
"salting": "Unique per-password random value to defeat precomputation",
"zero-knowledge proof": "Prove you know a secret without revealing it 🤫",
"merkle tree": "Hash tree summarizing data; efficient proofs 🌳",
"blockchain": "Append-only distributed ledger secured by consensus 📒",
"smart contract": "Code on blockchain that runs automatically on triggers",
"tell me about yourself":"Hey there! 😎 I’m your Crypto & Security AI Mentor. I’m here to help you understand encryption, decryption, cryptography, and data security in a simple and easy way. You can ask me about AES, RSA, hashing, keys, passwords, or general cybersecurity tips. I can also guide you on how to safely encrypt or decrypt messages for practice. Think of me like your mini crypto guide — whether it’s understanding how a key works, choosing the right encryption method, or learning about secure practices, I’ve got you covered. Just type your question, and I’ll explain it step by step in plain English, with examples if needed. Let’s make crypto simple and fun! 🚀"
         ,
         
         "cryptography": "Cryptography is securing information by converting it into unreadable form for unauthorized users 🔒",
"encryption": "Encryption converts plaintext into ciphertext using a key 🔐",
"decryption": "Decryption is converting ciphertext back into plaintext using the correct key 🔑",
"cipher": "A cipher is the algorithm used to encrypt or decrypt text 📜",

"key": "A key is secret information that controls encryption and decryption 🔑",
"strong key": "A strong key is random, long, and unpredictable 💪",
"reuse key": "Never reuse the same key across systems ❌",


"caesar cipher": "Caesar Cipher shifts letters in the alphabet by a fixed number 🔄",
"xor cipher": "XOR Cipher applies XOR between text and key. Simple but weak ⚡",
"substitution cipher": "Substitution Cipher replaces each letter with another symbol 🔤",

"aes": "AES is symmetric encryption. Use 128, 192, or 256-bit keys 🔑",
"rsa": "RSA is asymmetric. Public/private keys differ. Use 2048-bit or higher 🔐",
"symmetric encryption": "Symmetric uses one key for both encryption and decryption 🔄",
"asymmetric encryption": "Asymmetric uses a public key for encryption and a private key for decryption 🔑",

"hash": "Hashing is one-way. SHA-256 or SHA-512 is common 🛡️",
"password hash": "Passwords are stored as hashes, not plain text 🔐",
"salting": "Salting adds random data to a password before hashing to increase security 🧂",

"2fa": "Always enable Two-Factor Authentication for extra security 📱",
"password": "Use long, unique, random passwords and don’t reuse them 🔑",
"email security": "Avoid sharing passwords by email. If needed, send keys separately ✉️",

"hello": "Hello there! 🤖 How can I help you with crypto today?",
"hi": "Hi! Ready to talk about crypto? 💰",
"bye": "Goodbye! Stay safe with your crypto 🔒",
"thanks": "You're welcome! 😊"
,
         "yes": "Great! Ask me anything about crypto 🔍",
         "of course": "Of course! I'm here to help with your crypto questions 💬",
        "hi": "Hi! Ready to talk about crypto? 💰",
        "how are you": "I'm a bot, but I'm feeling electrified! ⚡",
        "ok": "Okay! any thing else about crypto?",
        "thanks": "You're welcome! Happy to help with your crypto questions 😊",
        "thank you": "You're welcome! If you have more crypto questions, just ask! 😊",
        "no": "No worries! If you have any crypto questions later, just ask! 🤖",
        "not really": "That's okay! If you have any crypto questions later, just ask! 🤖",
        "good": "Glad to hear! If you have any crypto questions, just ask! 🤖",
        "great": "Awesome! If you have any crypto questions, just ask! 🤖",
        "fantastic": "Fantastic! If you have any crypto questions, just ask! 🤖",
        "bye bye": "Goodbye! Stay safe with your crypto 🔒",
        "tata": "Goodbye! Stay safe with your crypto 🔒",
        "encryption": "Encryption is converting data into a coded form to prevent unauthorized access 🔐",
        "data security": "Data security involves protecting data from unauthorized access and corruption throughout its lifecycle 🛡️",
        "data": "Data is information processed or stored by a computer. It can be in various forms like text, images, or numbers 💾",
        "what is key": "A key is a piece of information that determines the output of a cryptographic algorithm 🔑",
        "i love u":"Thanks i love u too 😘",
        "who are u":"I'm your friendly crypto assistant bot! 😛 Here to help with all things crypto.",
        "who are you":"I'm your friendly crypto assistant bot! 😛 Here to help with all things crypto.",
        "bye": "Goodbye! Stay safe with your crypto 🔒"
    } 
    reply = next((v for k, v in crypto_fallbacks.items()  if k in user_msg), "Sorry i only talk about the message encryption 🤷‍♂️")
        
    return jsonify({"reply": f"😛: {reply}"})


# ---------------- EMAIL SENDING ROUTE ----------------
@app.route("/send_email", methods=["POST"])
@login_required
def send_email():
    try:
        data = request.get_json()
        to_email = data.get("to_email")
        subject = data.get("subject")
        body = data.get("body")

        if not all([to_email, subject, body]):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        # Direct SMTP implementation
        msg = MIMEMultipart()
        msg["From"] = f"{app.config['SMTP_FROM_NAME']} <{app.config['SMTP_USER']}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"])
        if app.config["SMTP_USE_TLS"]:
            server.starttls()
        server.login(app.config["SMTP_USER"], app.config["SMTP_PASS"])
        server.send_message(msg)
        server.quit()

        return jsonify({"status": "success", "message": "Email sent successfully!"})

    except Exception as e:
        print(f"Email error: {e}")
        return jsonify({"status": "error", "message": f"Failed to send email: {str(e)}"}), 500

        # Use your em
               
           

# ---------------- OTHER ROUTES (login, signup, profile, etc.) ----------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    
    form = LoginForm()
    if form.validate_on_submit():
        con = get_connection()
        with con.cursor() as cur:
            cur.execute("SELECT id, name, email, password_hash FROM users WHERE email=%s", (form.email.data,))
            row = cur.fetchone()
            if row:
                stored_hash = row["password_hash"]
                if stored_hash is None:
                    flash("This account was created with Google login. Please use Google login.", "warning")
                    return redirect(url_for("login"))
                if verify_password(form.password.data, stored_hash):
                    user = User(row["id"], row["name"], row["email"])
                    login_user(user)
                    flash("Welcome back!", "success")
                    return redirect(url_for("profile"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/signup", methods=["GET","POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        con = get_connection()
        with con.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (form.email.data,))
            if cur.fetchone():
                flash("Email already registered, please login.", "danger")
                return redirect(url_for("login"))
            cur.execute(
                "INSERT INTO users (name, email, password_hash, gender) VALUES (%s,%s,%s,%s)",
                (form.name.data, form.email.data, hash_password(form.password.data), form.gender.data)
            )
            flash("Account created! Please login.", "success")
            return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/profile")
@login_required
def profile():
    con = get_connection()
    with con.cursor() as cur:
        cur.execute("SELECT id, name, email, gender, created_at FROM users WHERE id=%s", (current_user.id,))
        me = cur.fetchone()
    return render_template("profile.html", me=me)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.get("/health")
def health():
    return {"ok": True}

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
