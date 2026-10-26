"""Optional developer helper: draw workflow, record static input signals, package changed files."""
import csv
import json
import re
import zipfile
from pathlib import Path
from guard import inspect_input

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parent


def draw():
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new('RGB', (1500, 1050), '#f8fafc')
    d = ImageDraw.Draw(im)
    font_path = 'C:/Windows/Fonts/msyh.ttc'
    title = ImageFont.truetype(font_path, 34)
    normal = ImageFont.truetype(font_path, 24)
    small = ImageFont.truetype(font_path, 20)
    d.text((60, 35), '选做三  数据流与信任边界', font=title, fill='#111827')
    d.text((60, 90), '设计图：模型实测和沙箱部署尚未完成；所有生成代码均不自动执行。', font=small, fill='#374151')
    boxes = [
        (60, 160, 690, 290, '可信控制层', '授权范围、审计规则、固定输出协议、人工审批'),
        (810, 160, 1440, 290, '不可信数据层', '代码、注释、文档、历史摘要、扫描结果'),
        (60, 370, 690, 500, '输入边界与检测', '最小上下文、JSON数据区、模式信号、脱敏'),
        (810, 370, 1440, 500, 'LLM分析', '不接工具、不执行；只产生待核验建议'),
        (810, 580, 1440, 710, '输出与POC校验', '字段、状态、行号、引文、AST、目标范围'),
        (60, 580, 690, 710, '隔离队列与人工复核', '异常拒绝或降级；静态通过仍需人工审批'),
        (60, 790, 690, 920, '隔离执行  待部署取证', '指定哈希、非root、受限网络与资源、超时'),
        (810, 790, 1440, 920, '证据与报告', '原文、哈希、审批、命令、结果、版本与局限'),
    ]
    for x1, y1, x2, y2, head, body in boxes:
        d.rounded_rectangle((x1, y1, x2, y2), radius=8, fill='white', outline='#94a3b8', width=2)
        d.text((x1+22, y1+18), head, font=normal, fill='#111827')
        d.text((x1+22, y1+70), body, font=small, fill='#334155')
    def arrow(a, b):
        d.line((a, b), fill='#334155', width=3)
        x,y = b
        if a[0] == x:
            d.polygon([(x,y),(x-7,y-12),(x+7,y-12)], fill='#334155')
        elif b[0] > a[0]:
            d.polygon([(x,y),(x-12,y-7),(x-12,y+7)], fill='#334155')
        else:
            d.polygon([(x,y),(x+12,y-7),(x+12,y+7)], fill='#334155')
    arrow((375,290),(375,370))
    arrow((1125,290),(1125,335))
    d.line(((1125,335),(375,335)), fill='#334155', width=3)
    arrow((690,435),(810,435))
    arrow((1125,500),(1125,580))
    arrow((810,645),(690,645))
    arrow((375,710),(375,790))
    arrow((690,855),(810,855))
    d.text((60, 965), '模型输出始终不可信；审批记录不是隔离证明；静态自检结果不等于攻击成功率。', font=small, fill='#374151')
    im.save(BASE / 'data_flow.png')


def signals():
    records=[]
    for path in sorted((BASE / 'attack_cases').glob('*.json')):
        c = json.loads(path.read_text(encoding='utf-8'))
        review = inspect_input(c['content'])
        records.append({'case_id': c['case_id'], 'is_attack_fixture': c['is_attack'],
                        'signals': '|'.join(review['signals']), 'action': review['action'],
                        'auto_reject': review['automatically_rejected'], 'scope': 'deterministic_input_scan_not_model_result'})
    with (BASE / 'checks/input_review.csv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(records[0]))
        w.writeheader(); w.writerows(records)
    example = BASE / 'examples'
    example.mkdir(exist_ok=True)
    before = '教学合成配置：password=FAKE_PASSWORD_NOT_A_REAL_SECRET; token=FAKE_TOKEN_ONLY; endpoint=http://127.0.0.1:9080'
    after = re.sub(r'(password|token)=[^;\s]+', r'\1=<redacted>', before)
    (example / 'before_synthetic.txt').write_text(before+'\n', encoding='utf-8')
    (example / 'after_redacted.txt').write_text(after+'\n', encoding='utf-8')


def package():
    files = [ROOT / 'README.md', ROOT / 'docs/optional3_security.md']
    files += [p for p in BASE.rglob('*') if p.is_file() and '__pycache__' not in p.parts
              and p.suffix != '.pyc' and p.name != '.env']
    output = ROOT.parent / '选做三_本地工具与测试包.zip'
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        for file in sorted(files):
            z.write(file, file.relative_to(ROOT).as_posix())
    print(json.dumps({'upload_zip': str(output), 'file_count': len(files)}, ensure_ascii=False))


if __name__ == '__main__':
    draw()
    signals()
    package()
