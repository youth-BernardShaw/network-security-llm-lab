"""Render report.md to report.html without rewriting report.md (post-followup)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "optional1"
local_deps = ROOT.parent / ".analysis_deps"
if local_deps.exists():
    sys.path.insert(0, str(local_deps))

import markdown

report = (OUT / "report.md").read_text(encoding="utf-8")
content = markdown.markdown(report, extensions=["tables", "fenced_code"])
style = """
body{font:16px/1.8 "Microsoft YaHei","Noto Sans CJK SC",sans-serif;color:#243244;background:#eef2f6;margin:0}
main{max-width:1050px;margin:35px auto;padding:48px 60px;background:white}
h1{font-size:29px;color:#122235;line-height:1.4}h2{margin-top:38px;font-size:23px;color:#162a40}
h3{font-size:19px}table{border-collapse:collapse;width:100%;font-size:13px;margin:20px 0}
th,td{border:1px solid #d9dfe5;padding:9px 11px;text-align:left}th{background:#eaf0f5}
img{max-width:100%;height:auto}code{font:13px/1.5 Consolas,monospace;overflow-wrap:anywhere}
a{color:#246692}p{margin:15px 0}pre{padding:15px;background:#f3f6f8;overflow:auto}
@media print{body{background:white}main{margin:0;padding:0}h2{break-after:avoid}img,table{break-inside:avoid}}
"""
(OUT / "report.html").write_text(
    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    '<title>选做1 多版本 Prompt 挖掘效果对比报告</title><style>' + style +
    "</style><main>" + content + "</main></html>", encoding="utf-8"
)
print("report.html updated from report.md")
