"""
Comprehensive Security Pattern Library

Provides 50+ vulnerability patterns across all major CWE categories.
Patterns are used for in-context learning and vulnerability detection.
"""

from src.knowledge.graph import SecurityKnowledgeGraph, SecurityPattern, PatternType


def initialize_pattern_library(kg: SecurityKnowledgeGraph) -> int:
    """
    Initialize knowledge graph with comprehensive pattern library.

    Returns:
        Number of patterns added
    """
    patterns = get_all_patterns()

    for pattern in patterns:
        kg.add_pattern(pattern)

    return len(patterns)


def get_all_patterns() -> list[SecurityPattern]:
    """Get all 50+ vulnerability patterns"""
    return [
        # === INJECTION FLAWS ===
        *get_sql_injection_patterns(),
        *get_command_injection_patterns(),
        *get_ldap_injection_patterns(),
        *get_xpath_injection_patterns(),
        *get_nosql_injection_patterns(),

        # === XSS VARIANTS ===
        *get_xss_patterns(),

        # === AUTHENTICATION & SESSION ===
        *get_authentication_patterns(),
        *get_session_management_patterns(),

        # === ACCESS CONTROL ===
        *get_access_control_patterns(),

        # === SENSITIVE DATA EXPOSURE ===
        *get_sensitive_data_patterns(),

        # === XML/XXE ===
        *get_xml_patterns(),

        # === DESERIALIZATION ===
        *get_deserialization_patterns(),

        # === SECURITY MISCONFIGURATION ===
        *get_misconfiguration_patterns(),

        # === CRYPTOGRAPHIC FAILURES ===
        *get_crypto_patterns(),

        # === SERVER-SIDE REQUEST FORGERY ===
        *get_ssrf_patterns(),

        # === PATH TRAVERSAL ===
        *get_path_traversal_patterns(),

        # === CSRF ===
        *get_csrf_patterns(),

        # === ADDITIONAL PATTERNS ===
        *get_regex_dos_patterns(),
        *get_race_condition_patterns(),
        *get_open_redirect_patterns(),
    ]


# === SQL INJECTION PATTERNS ===

def get_sql_injection_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-SQL-001",
            name="SQL Injection via String Formatting",
            pattern_type=PatternType.SQL_INJECTION,
            code_example='query = f"SELECT * FROM users WHERE id={user_id}"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-89"
        ),
        SecurityPattern(
            id="PATTERN-SQL-002",
            name="SQL Injection via String Concatenation",
            pattern_type=PatternType.SQL_INJECTION,
            code_example='query = "SELECT * FROM users WHERE name=\'" + username + "\'"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-89"
        ),
        SecurityPattern(
            id="PATTERN-SQL-003",
            name="SQL Injection in JavaScript",
            pattern_type=PatternType.SQL_INJECTION,
            code_example='const query = `SELECT * FROM users WHERE email=\'${email}\'`',
            language="javascript",
            risk_level="critical",
            cwe_id="CWE-89"
        ),
    ]


# === COMMAND INJECTION PATTERNS ===

def get_command_injection_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-CMD-001",
            name="OS Command Injection via subprocess",
            pattern_type=PatternType.COMMAND_INJECTION,
            code_example='subprocess.call("ping -c 1 " + user_input, shell=True)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-78"
        ),
        SecurityPattern(
            id="PATTERN-CMD-002",
            name="Command Injection via os.system",
            pattern_type=PatternType.COMMAND_INJECTION,
            code_example='os.system(f"ls {directory}")',
            language="python",
            risk_level="critical",
            cwe_id="CWE-78"
        ),
        SecurityPattern(
            id="PATTERN-CMD-003",
            name="Command Injection in Node.js",
            pattern_type=PatternType.COMMAND_INJECTION,
            code_example='exec(`git clone ${repo_url}`)',
            language="javascript",
            risk_level="critical",
            cwe_id="CWE-78"
        ),
    ]


# === LDAP INJECTION PATTERNS ===

def get_ldap_injection_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-LDAP-001",
            name="LDAP Injection in Search Filter",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='filter = f"(uid={username})(userPassword={password})"',
            language="python",
            risk_level="high",
            cwe_id="CWE-90"
        ),
    ]


# === XPATH INJECTION PATTERNS ===

def get_xpath_injection_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-XPATH-001",
            name="XPath Injection in Query",
            pattern_type=PatternType.SQL_INJECTION,  # Similar category
            code_example='xpath = f"//users[name=\'{username}\' and password=\'{password}\']"',
            language="python",
            risk_level="high",
            cwe_id="CWE-643"
        ),
    ]


# === NOSQL INJECTION PATTERNS ===

def get_nosql_injection_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-NOSQL-001",
            name="MongoDB NoSQL Injection",
            pattern_type=PatternType.SQL_INJECTION,
            code_example='db.users.find({"username": username, "password": password})',
            language="python",
            risk_level="critical",
            cwe_id="CWE-943"
        ),
        SecurityPattern(
            id="PATTERN-NOSQL-002",
            name="NoSQL Injection via $where",
            pattern_type=PatternType.SQL_INJECTION,
            code_example='db.users.find({"$where": f"this.username == \'{user}\'"})',
            language="python",
            risk_level="critical",
            cwe_id="CWE-943"
        ),
    ]


# === XSS PATTERNS ===

def get_xss_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-XSS-001",
            name="Reflected XSS in HTML",
            pattern_type=PatternType.XSS,
            code_example='return f"<h1>Hello {username}</h1>"',
            language="python",
            risk_level="high",
            cwe_id="CWE-79"
        ),
        SecurityPattern(
            id="PATTERN-XSS-002",
            name="Stored XSS in Database",
            pattern_type=PatternType.XSS,
            code_example='comment_html = f"<div>{user_comment}</div>"',
            language="python",
            risk_level="high",
            cwe_id="CWE-79"
        ),
        SecurityPattern(
            id="PATTERN-XSS-003",
            name="DOM-based XSS",
            pattern_type=PatternType.XSS,
            code_example='document.getElementById("output").innerHTML = userInput',
            language="javascript",
            risk_level="high",
            cwe_id="CWE-79"
        ),
        SecurityPattern(
            id="PATTERN-XSS-004",
            name="XSS in JavaScript String",
            pattern_type=PatternType.XSS,
            code_example='html = `<script>var user = "${userName}";</script>`',
            language="javascript",
            risk_level="high",
            cwe_id="CWE-79"
        ),
    ]


# === AUTHENTICATION PATTERNS ===

def get_authentication_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-AUTH-001",
            name="Hardcoded Credentials",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='password = "admin123"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-798"
        ),
        SecurityPattern(
            id="PATTERN-AUTH-002",
            name="Weak Password Hashing (MD5)",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='hashed = hashlib.md5(password.encode()).hexdigest()',
            language="python",
            risk_level="high",
            cwe_id="CWE-327"
        ),
        SecurityPattern(
            id="PATTERN-AUTH-003",
            name="Missing Password Salting",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='hashed = hashlib.sha256(password.encode()).hexdigest()',
            language="python",
            risk_level="high",
            cwe_id="CWE-759"
        ),
        SecurityPattern(
            id="PATTERN-AUTH-004",
            name="SQL Injection Authentication Bypass",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='query = f"SELECT * FROM users WHERE username=\'{user}\' AND password=\'{pwd}\'"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-89"
        ),
    ]


# === SESSION MANAGEMENT PATTERNS ===

def get_session_management_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-SESS-001",
            name="Session Fixation",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='session_id = request.GET.get("session_id")',
            language="python",
            risk_level="high",
            cwe_id="CWE-384"
        ),
        SecurityPattern(
            id="PATTERN-SESS-002",
            name="Missing Secure Cookie Flag",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='response.set_cookie("session_id", session_id)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-614"
        ),
        SecurityPattern(
            id="PATTERN-SESS-003",
            name="Missing HttpOnly Cookie Flag",
            pattern_type=PatternType.XSS,
            code_example='response.set_cookie("token", token, secure=True)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-1004"
        ),
    ]


# === ACCESS CONTROL PATTERNS ===

def get_access_control_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-AC-001",
            name="Missing Authorization Check",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='def delete_user(user_id): db.delete(user_id)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-862"
        ),
        SecurityPattern(
            id="PATTERN-AC-002",
            name="Insecure Direct Object Reference",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='user = User.query.get(request.args["id"])',
            language="python",
            risk_level="high",
            cwe_id="CWE-639"
        ),
        SecurityPattern(
            id="PATTERN-AC-003",
            name="Path Traversal in File Access",
            pattern_type=PatternType.PATH_TRAVERSAL,
            code_example='file_path = "/uploads/" + filename',
            language="python",
            risk_level="high",
            cwe_id="CWE-22"
        ),
    ]


# === SENSITIVE DATA PATTERNS ===

def get_sensitive_data_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-DATA-001",
            name="API Key in Source Code",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='api_key = "sk-1234567890abcdef"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-798"
        ),
        SecurityPattern(
            id="PATTERN-DATA-002",
            name="Sensitive Data in Logs",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='logging.info(f"User {username} logged in with password {password}")',
            language="python",
            risk_level="high",
            cwe_id="CWE-532"
        ),
        SecurityPattern(
            id="PATTERN-DATA-003",
            name="Sensitive Data in URL",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='redirect(f"/reset?token={reset_token}")',
            language="python",
            risk_level="medium",
            cwe_id="CWE-598"
        ),
        SecurityPattern(
            id="PATTERN-DATA-004",
            name="Unencrypted Sensitive Data Storage",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='with open("users.txt", "w") as f: f.write(f"{user}:{password}")',
            language="python",
            risk_level="high",
            cwe_id="CWE-312"
        ),
    ]


# === XML/XXE PATTERNS ===

def get_xml_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-XXE-001",
            name="XML External Entity Injection",
            pattern_type=PatternType.XXE,
            code_example='tree = ET.parse(user_xml)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-611"
        ),
        SecurityPattern(
            id="PATTERN-XXE-002",
            name="Unsafe XML Parser Configuration",
            pattern_type=PatternType.XXE,
            code_example='parser = ET.XMLParser(resolve_entities=True)',
            language="python",
            risk_level="high",
            cwe_id="CWE-611"
        ),
    ]


# === DESERIALIZATION PATTERNS ===

def get_deserialization_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-DESER-001",
            name="Insecure Pickle Deserialization",
            pattern_type=PatternType.INSECURE_DESERIALIZATION,
            code_example='data = pickle.loads(user_data)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-502"
        ),
        SecurityPattern(
            id="PATTERN-DESER-002",
            name="YAML Unsafe Load",
            pattern_type=PatternType.INSECURE_DESERIALIZATION,
            code_example='config = yaml.load(user_config)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-502"
        ),
        SecurityPattern(
            id="PATTERN-DESER-003",
            name="Eval on User Input",
            pattern_type=PatternType.INSECURE_DESERIALIZATION,
            code_example='result = eval(user_expression)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-95"
        ),
    ]


# === SECURITY MISCONFIGURATION PATTERNS ===

def get_misconfiguration_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-CONFIG-001",
            name="Debug Mode Enabled in Production",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='app = Flask(__name__)\napp.debug = True',
            language="python",
            risk_level="high",
            cwe_id="CWE-489"
        ),
        SecurityPattern(
            id="PATTERN-CONFIG-002",
            name="CORS Allow All Origins",
            pattern_type=PatternType.CSRF,
            code_example='@app.after_request\ndef after(r): r.headers["Access-Control-Allow-Origin"] = "*"',
            language="python",
            risk_level="medium",
            cwe_id="CWE-346"
        ),
        SecurityPattern(
            id="PATTERN-CONFIG-003",
            name="Overly Permissive File Permissions",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='os.chmod("config.json", 0o777)',
            language="python",
            risk_level="high",
            cwe_id="CWE-732"
        ),
    ]


# === CRYPTOGRAPHIC FAILURES ===

def get_crypto_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-CRYPTO-001",
            name="Weak Random Number Generation",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='token = random.randint(1000, 9999)',
            language="python",
            risk_level="high",
            cwe_id="CWE-338"
        ),
        SecurityPattern(
            id="PATTERN-CRYPTO-002",
            name="Insecure SSL/TLS Configuration",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='requests.get(url, verify=False)',
            language="python",
            risk_level="high",
            cwe_id="CWE-295"
        ),
        SecurityPattern(
            id="PATTERN-CRYPTO-003",
            name="Weak Encryption Algorithm (DES)",
            pattern_type=PatternType.AUTHENTICATION_BYPASS,
            code_example='cipher = DES.new(key, DES.MODE_ECB)',
            language="python",
            risk_level="critical",
            cwe_id="CWE-327"
        ),
        SecurityPattern(
            id="PATTERN-CRYPTO-004",
            name="Hardcoded Encryption Key",
            pattern_type=PatternType.HARDCODED_SECRETS,
            code_example='key = b"0123456789abcdef"',
            language="python",
            risk_level="critical",
            cwe_id="CWE-321"
        ),
    ]


# === SSRF PATTERNS ===

def get_ssrf_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-SSRF-001",
            name="Server-Side Request Forgery",
            pattern_type=PatternType.SSRF,
            code_example='response = requests.get(user_url)',
            language="python",
            risk_level="high",
            cwe_id="CWE-918"
        ),
        SecurityPattern(
            id="PATTERN-SSRF-002",
            name="SSRF via URL Parameter",
            pattern_type=PatternType.SSRF,
            code_example='img_url = request.args.get("url")\nimg = urlopen(img_url)',
            language="python",
            risk_level="high",
            cwe_id="CWE-918"
        ),
    ]


# === PATH TRAVERSAL PATTERNS ===

def get_path_traversal_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-PATH-001",
            name="Path Traversal in File Operations",
            pattern_type=PatternType.PATH_TRAVERSAL,
            code_example='with open(f"/data/{filename}", "r") as f: content = f.read()',
            language="python",
            risk_level="high",
            cwe_id="CWE-22"
        ),
        SecurityPattern(
            id="PATTERN-PATH-002",
            name="Zip Slip Vulnerability",
            pattern_type=PatternType.PATH_TRAVERSAL,
            code_example='zipfile.extractall(dest_dir)',
            language="python",
            risk_level="high",
            cwe_id="CWE-22"
        ),
    ]


# === CSRF PATTERNS ===

def get_csrf_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-CSRF-001",
            name="Missing CSRF Protection",
            pattern_type=PatternType.CSRF,
            code_example='@app.route("/transfer", methods=["POST"])\ndef transfer(): amount = request.form["amount"]',
            language="python",
            risk_level="medium",
            cwe_id="CWE-352"
        ),
        SecurityPattern(
            id="PATTERN-CSRF-002",
            name="CSRF in State-Changing GET",
            pattern_type=PatternType.CSRF,
            code_example='@app.route("/delete/<id>")\ndef delete(id): db.delete(id)',
            language="python",
            risk_level="high",
            cwe_id="CWE-352"
        ),
    ]


# === REGEX DOS PATTERNS ===

def get_regex_dos_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-REDOS-001",
            name="Regular Expression Denial of Service",
            pattern_type=PatternType.COMMAND_INJECTION,  # Similar risk category
            code_example='re.match(r"(a+)+b", user_input)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-1333"
        ),
        SecurityPattern(
            id="PATTERN-REDOS-002",
            name="Catastrophic Backtracking in Regex",
            pattern_type=PatternType.COMMAND_INJECTION,
            code_example='re.findall(r"(.*a){x}b", long_string)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-1333"
        ),
    ]


# === RACE CONDITION PATTERNS ===

def get_race_condition_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-RACE-001",
            name="Time-of-Check Time-of-Use (TOCTOU)",
            pattern_type=PatternType.PATH_TRAVERSAL,
            code_example='if os.path.exists(file): with open(file, "w") as f: f.write(data)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-367"
        ),
        SecurityPattern(
            id="PATTERN-RACE-002",
            name="Race Condition in File Creation",
            pattern_type=PatternType.PATH_TRAVERSAL,
            code_example='if not os.path.exists(temp_file): open(temp_file, "w").write(secret)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-362"
        ),
    ]


# === OPEN REDIRECT PATTERNS ===

def get_open_redirect_patterns() -> list[SecurityPattern]:
    return [
        SecurityPattern(
            id="PATTERN-REDIR-001",
            name="Open Redirect via URL Parameter",
            pattern_type=PatternType.XSS,
            code_example='redirect_url = request.args.get("next")\nreturn redirect(redirect_url)',
            language="python",
            risk_level="medium",
            cwe_id="CWE-601"
        ),
        SecurityPattern(
            id="PATTERN-REDIR-002",
            name="Unvalidated Redirect in JavaScript",
            pattern_type=PatternType.XSS,
            code_example='window.location = params.get("redirect")',
            language="javascript",
            risk_level="medium",
            cwe_id="CWE-601"
        ),
    ]


if __name__ == "__main__":
    # Test pattern library
    from src.knowledge.graph import SecurityKnowledgeGraph
    import tempfile

    # Create test knowledge graph
    kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())

    # Initialize pattern library
    count = initialize_pattern_library(kg)

    print(f"✓ Initialized pattern library with {count} patterns")
    print(f"\nPattern Distribution:")

    # Count by type
    from collections import Counter
    pattern_types = Counter(p.pattern_type.value for p in get_all_patterns())

    for ptype, count in pattern_types.most_common():
        print(f"  {ptype}: {count}")

    # Show sample patterns
    print(f"\nSample Patterns:")
    for pattern in get_all_patterns()[:5]:
        print(f"  - {pattern.id}: {pattern.name} ({pattern.risk_level})")

    print(f"\nTotal Patterns: {len(get_all_patterns())}")
