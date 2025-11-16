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
