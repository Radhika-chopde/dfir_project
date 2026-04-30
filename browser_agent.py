import os, re, math, sqlite3, shutil, pathlib
from flask import Flask, request, jsonify
from db_utils import save_to_db

app = Flask(__name__)

SAFE_INFRASTRUCTURE = [
    r".*\.google\.com$", r".*\.microsoft\.com$", r".*\.amazonaws\.com$",
    r".*\.cloudfront\.net$", r".*\.gstatic\.com$", r".*\.apple\.com$",
    r".*\.windowsupdate\.com$", r".*\.github\.com$", r".*\.office\.com$",
]
TLD_SUSPICIOUS = [".onion", ".pw", ".bid", ".cc", ".icu", ".top", ".xyz", ".to"]
TLD_CRITICAL   = [".zip", ".mov", ".sh"]
RISK_FACTORS   = {
    "Data_Exfiltration": (r"(temp-mail|transfer\.sh|mega\.nz/file/|anonfiles\.com|sendspace\.com)", 5),
    "C2_Indicators":     (r"(clk\.php|click\.php\?|/[a-z0-9]{12,}\.php$)", 4),
    "Anonymization":     (r"(torproject|protonvpn|mullvad|nordvpn|tunnelbear)", 4),
    "Piracy_Source":     (r"(torrent|crack|keygen|hianime|fmovies|anikai)", 4),
}

def get_browser_history_paths():
    """Returns all discovered browser history DB paths across browsers and profiles."""
    paths = []
    username = os.getlogin()
    base = pathlib.Path(f"C:/Users/{username}/AppData/Local")

    # Chrome — all profiles
    chrome_base = base / "Google/Chrome/User Data"
    if chrome_base.exists():
        for profile_dir in chrome_base.iterdir():
            h = profile_dir / "History"
            if h.exists():
                paths.append(("Chrome", str(profile_dir.name), str(h)))

    # Edge — all profiles
    edge_base = base / "Microsoft/Edge/User Data"
    if edge_base.exists():
        for profile_dir in edge_base.iterdir():
            h = profile_dir / "History"
            if h.exists():
                paths.append(("Edge", str(profile_dir.name), str(h)))

    # Firefox — all profiles
    ff_base = pathlib.Path(f"C:/Users/{username}/AppData/Roaming/Mozilla/Firefox/Profiles")
    if ff_base.exists():
        for profile_dir in ff_base.iterdir():
            h = profile_dir / "places.sqlite"
            if h.exists():
                paths.append(("Firefox", str(profile_dir.name), str(h)))

    return paths

def safe_copy_sqlite(src, dest):
    """Uses the SQLite backup API to copy a potentially locked database."""
    try:
        src_conn  = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        dest_conn = sqlite3.connect(dest)
        src_conn.backup(dest_conn)
        src_conn.close()
        dest_conn.close()
        return True
    except Exception as e:
        print(f"[BrowserAgent] Could not copy {src}: {e}")
        return False

def extract_hostname(domain):
    """
    Strips www. prefix and TLD suffix before entropy calculation.
    We want to measure entropy of just the meaningful part:
    'www.kimi.com'        → 'kimi'
    'a7x9kp2mq.top'      → 'a7x9kp2mq'
    'subdomain.evil.xyz'  → 'subdomain.evil'
    """
    # Strip www. prefix
    if domain.startswith("www."):
        domain = domain[4:]

    # Strip the TLD (last part after final dot)
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        domain = parts[0]   # 'kimi.com' → 'kimi', 'evil.xyz' → 'evil'

    return domain


def calculate_entropy(domain):
    if not domain:
        return 0
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * math.log(p, 2) for p in prob if p > 0)


def calculate_url_risk(url, visit_count):
    score    = 0
    reasons  = []
    url_lower = url.lower()
    domain   = url_lower.split('://')[-1].split('/')[0].split('?')[0].split(':')[0]

    if any(re.match(p, domain) for p in SAFE_INFRASTRUCTURE):
        return 0, []

    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", domain):
        if not any(domain.startswith(p) for p in ["127.", "192.168.", "10.", "172.16."]):
            score += 5
            reasons.append("Direct public IP access")

    for category, (pattern, weight) in RISK_FACTORS.items():
        if re.search(pattern, url_lower):
            score += weight
            reasons.append(category.replace("_", " "))

    if any(domain.endswith(t) for t in TLD_SUSPICIOUS):
        score += 3
        reasons.append("Low-reputation TLD")
    elif any(domain.endswith(t) for t in TLD_CRITICAL):
        score += 6
        reasons.append("High-risk TLD")

    # ── DGA detection on the CLEAN hostname only ──────────────────────
    clean_host = extract_hostname(domain)   # strip www. and TLD first
    entropy    = calculate_entropy(clean_host)

    # Raised threshold: 3.5 on clean hostname AND minimum length of 8
    # Real DGA names: 'a7x9kp2mq' scores ~3.17, 'k3xm9pla2f' scores ~3.32
    # Real words:     'google' scores 2.58, 'kimi' scores 1.5
    if entropy > 4.2 and len(clean_host) >= 8:
        score += 4
        reasons.append(f"High-entropy domain ({entropy:.2f})")
    # ──────────────────────────────────────────────────────────────────

    if score > 0 and visit_count > 30:
        score -= 2
        reasons.append("Habitual visit (trust discount)")
    elif score > 0 and visit_count < 2:
        score += 2
        reasons.append("First-time domain visit")

    return score, reasons

@app.route('/scan_browser', methods=['POST'])
def scan_browser():
    data             = request.get_json()
    investigation_id = data.get('investigation_id')
    findings_count   = 0
    history_paths    = get_browser_history_paths()

    if not history_paths:
        return jsonify({"message": "No browser history files found"}), 200

    for browser, profile, history_path in history_paths:
        temp_db = f"history_{investigation_id}_{browser}_{profile}.db"
        if not safe_copy_sqlite(history_path, temp_db):
            continue

        try:
            conn = sqlite3.connect(temp_db)
            cur  = conn.cursor()

            if browser == "Firefox":
                cur.execute("SELECT url, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 500")
            else:
                cur.execute("SELECT url, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 500")

            for url, visit_count in cur.fetchall():
                risk_score, reasons = calculate_url_risk(url or "", visit_count or 0)
                if risk_score >= 6:
                    desc = f"[{browser}/{profile}] Risk {risk_score}: {', '.join(reasons)}. URL: {url[:80]}"
                    save_to_db("BrowserAgent", "Heuristic Web Alert", desc, investigation_id, f"{browser} History")
                    findings_count += 1

            conn.close()
        except Exception as e:
            print(f"[BrowserAgent] Error scanning {browser}/{profile}: {e}")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    return jsonify({"status": "complete", "matches_found": findings_count})

if __name__ == '__main__':
    app.run(port=5007, debug=False)