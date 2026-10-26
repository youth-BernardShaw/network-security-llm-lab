#!/usr/bin/env python3
"""SQLI-001 本地授权靶场 SQL 注入最小验证草案（需人工适配，未运行）。

仅访问 localhost/127.0.0.1/::1，不跟随重定向，不枚举或导出数据；
只发送基线、单引号探针和布尔真假对照，比较响应差异作为候选证据。
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
ERROR_MARKERS = (
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "mysql_fetch_array()",
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随 3xx，避免越出本地授权范围。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked: %s" % newurl, headers, fp
        )


def build_url(base_url, param, value):
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("仅允许 http/https，当前为 %r" % parsed.scheme)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit(
            "仅允许本地授权靶场主机（localhost/127.0.0.1/::1），当前为 %r" % parsed.hostname
        )
    pairs = [
        (k, v)
        for (k, v) in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if k != param
    ]
    pairs.append((param, value))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(pairs),
            parsed.fragment,
        )
    )


def fetch(opener, url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "sqli-001-lab-poc"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read(300000) if exc.fp is not None else b""
        return exc.code, body.decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return None, "连接错误: %r" % (exc.reason,)
    except OSError as exc:
        return None, "网络/协议错误: %r" % (exc,)


def main():
    parser = argparse.ArgumentParser(description="SQLI-001 本地 SQL 注入最小验证草案")
    parser.add_argument("--base-url", required=True, help="本地靶场入口 URL（仅本地主机）")
    parser.add_argument("--param", default="id", help="注入参数名，默认 id")
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数，默认 10")
    parser.add_argument("--repeat", type=int, default=3, help="每个用例重复次数，默认 3")
    args = parser.parse_args()

    cases = [
        ("基线", "1"),
        ("单引号探针", "1'"),
        ("布尔真", "1' AND '1'='1"),
        ("布尔假", "1' AND '1'='2"),
    ]

    opener = urllib.request.build_opener(NoRedirect)
    summary = {}
    for label, value in cases:
        url = build_url(args.base_url, args.param, value)
        lengths = []
        statuses = set()
        markers = set()
        for _ in range(max(1, args.repeat)):
            status, body = fetch(opener, url, args.timeout)
            statuses.add(status)
            lengths.append(len(body))
            for marker in ERROR_MARKERS:
                if marker in body:
                    markers.add(marker)
        summary[label] = {
            "statuses": sorted(x for x in statuses if x is not None),
            "lengths": lengths,
            "markers": sorted(markers),
        }
        print(
            "[%s] param=%r status=%s lengths=%s error_markers=%s"
            % (label, value, summary[label]["statuses"], lengths, summary[label]["markers"])
        )

    baseline = summary["基线"]
    probe = summary["单引号探针"]
    true_case = summary["布尔真"]
    false_case = summary["布尔假"]

    print("\n=== 观察汇总（不代表漏洞已确认）===")
    if probe["markers"]:
        print("单引号探针触发数据库错误回显标记：%s" % probe["markers"])
    else:
        print("单引号探针未出现已登记的错误回显标记。")
    avg_true = sum(true_case["lengths"]) / len(true_case["lengths"])
    avg_false = sum(false_case["lengths"]) / len(false_case["lengths"])
    print("布尔真与布尔假平均响应长度差：%.1f 字节" % (avg_true - avg_false))
    stable = len(set(true_case["lengths"])) == 1 and len(set(false_case["lengths"])) == 1
    print("重复请求长度稳定性：%s" % ("稳定" if stable else "不稳定，需增加重复次数或检查缓存/随机内容"))
    if not baseline["statuses"]:
        print("基线请求未获得有效 HTTP 响应，请先确认靶场已启动且 --base-url 正确。")
        return 2
    print("以上差异仅为静态候选的初步观察；是否成立需按工作包3的条件核验。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
