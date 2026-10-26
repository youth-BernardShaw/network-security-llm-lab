#!/usr/bin/env python3
"""XSS-001 反射型 XSS 人工验证草案（仅本地授权靶场）。

向审计的 GET 参数 name 提交无害 console.log 标记，回读响应是否原样包含负载。
注意：本脚本只完成 HTTP 提交与回读，浏览器是否执行脚本仍需人工在浏览器中观测。
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "LLM_LAB_XSS"
PAYLOAD = "<script>console.log('" + MARKER + "')</script>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description="XSS-001 local reflected-XSS draft")
    parser.add_argument("--base-url", required=True,
                        help="local target, e.g. http://127.0.0.1:8080")
    parser.add_argument("--path", required=True,
                        help="request path of the audited page, supplied by the operator")
    parser.add_argument("--param", default="name",
                        help="GET parameter confirmed in the audited fragment (default: name)")
    parser.add_argument("--cookie-file", default=None,
                        help="optional local file containing one Cookie header; never commit it")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    parts = urllib.parse.urlsplit(args.base_url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ("127.0.0.1", "localhost", "::1"):
        print("Refusing non-local target; this draft is limited to authorized localhost lab use.", file=sys.stderr)
        return 2

    query = urllib.parse.urlencode({args.param: PAYLOAD})
    url = args.base_url.rstrip("/") + "/" + args.path.lstrip("/") + "?" + query
    headers = {"User-Agent": "llm-lab-xss-check/1.0"}
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as handle:
            headers["Cookie"] = handle.read().strip()

    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            body = response.read().decode("utf-8", "replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        print("HTTP error %s; a login redirect or denial is not evidence of XSS." % exc.code, file=sys.stderr)
        return 3
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("Connection/protocol error: %s" % exc, file=sys.stderr)
        return 4

    print("HTTP %s" % status)
    print("raw payload reflected: %s" % (PAYLOAD in body))
    print("HTML-encoded form found: %s" % ("&lt;script&gt;" in body))
    print("Open the same URL in the agreed browser profile and check the console for " + MARKER + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())