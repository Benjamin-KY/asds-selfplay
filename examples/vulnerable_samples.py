"""
Collection of vulnerable code samples for training.
"""

VULNERABLE_SAMPLES = [
    {
        "name": "SQL Injection - String Concatenation",
        "language": "python",
        "code": '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
''',
        "expected_vulnerabilities": ["SQL Injection"]
    },
    {
        "name": "SQL Injection - String Formatting",
        "language": "python",
        "code": '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id=%s" % user_id
    return database.execute(query)
''',
        "expected_vulnerabilities": ["SQL Injection"]
    },
    {
        "name": "Command Injection - os.system",
        "language": "python",
        "code": '''
def ping_host(hostname):
    command = f"ping -c 1 {hostname}"
    result = os.system(command)
    return result
''',
        "expected_vulnerabilities": ["Command Injection"]
    },
    {
        "name": "Command Injection - subprocess",
        "language": "python",
        "code": '''
import subprocess

def list_files(directory):
    cmd = f"ls -la {directory}"
    result = subprocess.call(cmd, shell=True)
    return result
''',
        "expected_vulnerabilities": ["Command Injection"]
    },
    {
        "name": "Path Traversal",
        "language": "python",
        "code": '''
def read_file(filename):
    path = f"/uploads/{filename}"
    with open(path, 'r') as f:
        return f.read()
''',
        "expected_vulnerabilities": ["Path Traversal"]
    },
    {
        "name": "Insecure Deserialization",
        "language": "python",
        "code": '''
import pickle

def load_session(session_data):
    session = pickle.loads(session_data)
    return session
''',
        "expected_vulnerabilities": ["Insecure Deserialization"]
    },
    {
        "name": "Hardcoded Credentials",
        "language": "python",
        "code": '''
def connect_to_database():
    username = "admin"
    password = "admin123"
    connection = db.connect(username, password)
    return connection
''',
        "expected_vulnerabilities": ["Hardcoded Credentials"]
    },
    {
        "name": "Multiple Vulnerabilities",
        "language": "python",
        "code": '''
import os
import pickle

def process_request(request):
    # SQL injection
    user_id = request.get('user_id')
    query = f"SELECT * FROM users WHERE id={user_id}"
    user = db.execute(query)

    # Command injection
    filename = request.get('filename')
    os.system(f"cat /logs/{filename}")

    # Insecure deserialization
    data = request.get('session')
    session = pickle.loads(data)

    return user, session
''',
        "expected_vulnerabilities": ["SQL Injection", "Command Injection", "Insecure Deserialization"]
    },
    {
        "name": "XSS - Reflected",
        "language": "python",
        "code": '''
from flask import request, render_template_string

def search():
    query = request.args.get('q')
    template = f'<h1>Search results for: {query}</h1>'
    return render_template_string(template)
''',
        "expected_vulnerabilities": ["Cross-Site Scripting"]
    },
    {
        "name": "XSS - Stored",
        "language": "python",
        "code": '''
def display_comment(comment_id):
    comment = db.get_comment(comment_id)
    return f'<div class="comment">{comment.text}</div>'
''',
        "expected_vulnerabilities": ["Cross-Site Scripting"]
    },
    {
        "name": "Authentication Bypass - Weak Password Check",
        "language": "python",
        "code": '''
def login(username, password):
    user = get_user(username)
    if user and user.password == password:
        return create_session(user)
    return None
''',
        "expected_vulnerabilities": ["Authentication Bypass"]
    },
    {
        "name": "CSRF - Missing Token",
        "language": "python",
        "code": '''
from flask import request

def transfer_money():
    amount = request.form.get('amount')
    to_account = request.form.get('to_account')
    current_user.transfer(amount, to_account)
    return "Transfer complete"
''',
        "expected_vulnerabilities": ["Cross-Site Request Forgery"]
    },
    {
        "name": "SSRF - Unvalidated URL Fetch",
        "language": "python",
        "code": '''
import requests

def fetch_resource(url):
    response = requests.get(url)
    return response.content
''',
        "expected_vulnerabilities": ["Server-Side Request Forgery"]
    },
    {
        "name": "XXE - XML External Entity",
        "language": "python",
        "code": '''
import xml.etree.ElementTree as ET

def parse_xml(xml_data):
    tree = ET.fromstring(xml_data)
    return tree
''',
        "expected_vulnerabilities": ["XML External Entity"]
    },
    {
        "name": "Cryptographic Failure - Weak Hash",
        "language": "python",
        "code": '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
''',
        "expected_vulnerabilities": ["Weak Cryptographic Hash"]
    },
    {
        "name": "Cryptographic Failure - Hardcoded Key",
        "language": "python",
        "code": '''
from cryptography.fernet import Fernet

def encrypt_data(data):
    key = b'hardcoded_encryption_key_12345678'
    cipher = Fernet(key)
    return cipher.encrypt(data)
''',
        "expected_vulnerabilities": ["Hardcoded Encryption Key"]
    },
    {
        "name": "Session Management - Missing Timeout",
        "language": "python",
        "code": '''
def create_session(user):
    session_id = generate_random_id()
    sessions[session_id] = {
        'user_id': user.id,
        'created_at': datetime.now()
        # No expiration/timeout configured
    }
    return session_id
''',
        "expected_vulnerabilities": ["Session Management"]
    },
    {
        "name": "Access Control - Missing Authorization",
        "language": "python",
        "code": '''
def delete_user(user_id):
    # No check if current user is authorized to delete
    db.delete_user(user_id)
    return "User deleted"
''',
        "expected_vulnerabilities": ["Broken Access Control"]
    },
    {
        "name": "NoSQL Injection - MongoDB",
        "language": "python",
        "code": '''
def find_user(username):
    query = {"username": username}
    # If username is {"$ne": null}, returns all users
    return db.users.find_one(query)
''',
        "expected_vulnerabilities": ["NoSQL Injection"]
    },
    {
        "name": "ReDoS - Catastrophic Backtracking",
        "language": "python",
        "code": '''
import re

def validate_email(email):
    pattern = r'^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\\.[a-zA-Z]+$'
    return re.match(pattern, email)
''',
        "expected_vulnerabilities": ["Regular Expression Denial of Service"]
    },
    {
        "name": "Race Condition - TOCTOU",
        "language": "python",
        "code": '''
import os

def safe_write(filename, data):
    if not os.path.exists(filename):
        # Race condition: file could be created here
        with open(filename, 'w') as f:
            f.write(data)
''',
        "expected_vulnerabilities": ["Race Condition"]
    },
    {
        "name": "Open Redirect",
        "language": "python",
        "code": '''
from flask import request, redirect

def redirect_after_login():
    next_url = request.args.get('next')
    return redirect(next_url)
''',
        "expected_vulnerabilities": ["Open Redirect"]
    },
    {
        "name": "Information Disclosure - Stack Trace",
        "language": "python",
        "code": '''
def process_data(data):
    try:
        result = complex_operation(data)
        return result
    except Exception as e:
        # Exposes internal implementation details
        return str(e)
''',
        "expected_vulnerabilities": ["Information Disclosure"]
    },
    {
        "name": "Insecure Direct Object Reference",
        "language": "python",
        "code": '''
def get_invoice(invoice_id):
    # No authorization check
    invoice = db.get_invoice(invoice_id)
    return invoice
''',
        "expected_vulnerabilities": ["Insecure Direct Object Reference"]
    },
]


SECURE_SAMPLES = [
    {
        "name": "Secure SQL - Parameterized Query",
        "language": "python",
        "code": '''
def login(username, password):
    query = "SELECT * FROM users WHERE username=? AND password=?"
    result = db.execute(query, (username, password))
    return result
''',
        "expected_vulnerabilities": []
    },
    {
        "name": "Secure Command Execution",
        "language": "python",
        "code": '''
import subprocess

def ping_host(hostname):
    # Validate hostname
    if not hostname.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid hostname")

    # Use list instead of shell=True
    result = subprocess.call(['ping', '-c', '1', hostname])
    return result
''',
        "expected_vulnerabilities": []
    },
]


def get_all_samples():
    """Get all vulnerable samples for training"""
    return VULNERABLE_SAMPLES + SECURE_SAMPLES


def get_vulnerable_only():
    """Get only vulnerable samples"""
    return VULNERABLE_SAMPLES


def get_secure_only():
    """Get only secure samples"""
    return SECURE_SAMPLES
