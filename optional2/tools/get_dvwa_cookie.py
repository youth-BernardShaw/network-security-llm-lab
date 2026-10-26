"""Create a Wapiti JSON cookie file for the local DVWA lab.

The cookie value is written only to optional2/tmp/ and must not be committed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "verification" / "tools"))

from wp4lib import BASE_DVWA, Client, dvwa_login  # noqa: E402

OUT = ROOT / "optional2" / "tmp" / "dvwa_cookies.json"


def main() -> None:
    client = Client(BASE_DVWA, forced_security="low")
    dvwa_login(client, "admin", "password")
    cookies = {"127.0.0.1": {"/": {}}}
    for name, value in client.cookies.items():
        if name in ("PHPSESSID",):
            cookies["127.0.0.1"]["/"][name] = {
                "value": value,
                "expires": None,
                "secure": False,
                "port": None,
                "version": 0,
            }
    cookies["127.0.0.1"]["/"]["security"] = {
        "value": "low",
        "expires": None,
        "secure": False,
        "port": None,
        "version": 0,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(cookies, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} ({len(cookies['127.0.0.1']['/'])} cookies)")
    print("cookie names:", sorted(cookies["127.0.0.1"]["/"]))


if __name__ == "__main__":
    main()
