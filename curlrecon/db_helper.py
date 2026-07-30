import json
from pathlib import Path

# Provide a fallback, built-in database just in case.
FALLBACK_DB = {
    "WordPress": {
        "4.7.0": "CVE-2017-1001000 (REST API RCE)",
        "4.7.1": "CVE-2017-1001000 (REST API RCE)",
        "5.0.0": "CVE-2019-8942 (RCE)",
    },
    "Nginx": {
        "1.16.0": "CVE-2019-9511 (HTTP/2 Data Dribble)",
        "1.16.1": "CVE-2019-9511 (HTTP/2 Data Dribble)",
    }
}

def load_cve_db(db_path="cve_database.json"):
    p = Path(db_path)
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return FALLBACK_DB
