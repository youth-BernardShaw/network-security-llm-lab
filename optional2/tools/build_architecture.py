"""Draw the optional-2 integration architecture diagram (PNG)."""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "optional2" / "integration_architecture.png"
FONT = "C:/Windows/Fonts/msyh.ttc"
BOLD = "C:/Windows/Fonts/msyhbd.ttc"

W, H = 1900, 1180
BG = "#f6f8fb"
INK = "#1f2937"
MUTED = "#4b5563"
LINE = "#64748b"


def font(size: int, bold: bool = False):
    return ImageFont.truetype(BOLD if bold else FONT, size)


def box(draw, xy, title, body, fill, border):
    x1, y1, x2, y2 = xy
    draw.rounded_rectangle(xy, radius=16, fill=fill, outline=border, width=3)
    draw.text((x1 + 20, y1 + 14), title, font=font(26, True), fill=INK)
    y = y1 + 54
    for line in body:
        draw.text((x1 + 20, y), line, font=font(18), fill=MUTED)
        y += 27


def arrow(draw, start, end, color=LINE, number=None):
    draw.line([start, end], fill=color, width=3)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    for offset in (0.5, -0.5):
        x = end[0] - 15 * math.cos(angle + offset)
        y = end[1] - 15 * math.sin(angle + offset)
        draw.line([end, (x, y)], fill=color, width=3)
    if number:
        mx, my = (start[0] + end[0]) // 2, (start[1] + end[1]) // 2
        draw.ellipse((mx - 13, my - 13, mx + 13, my + 13), fill="#ffffff", outline=color, width=2)
        draw.text((mx - 7, my - 12), number, font=font(18, True), fill=color)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.text((60, 35), "选做2：LLM 与传统扫描器联动架构", font=font(40, True), fill=INK)
    draw.text((60, 92), "两条主流程 + 统一归一化 + POC 复核：让“模型候选”和“扫描器告警”进入同一证据链",
              font=font(21), fill=MUTED)

    box(draw, (60, 150, 470, 320), "范围与授权", [
        "仅 127.0.0.1:9080 / 9081",
        "host allowlist / 速率 / 备份",
        "scope.md",
        "endpoint_inventory.csv",
    ], "#e2e8f0", "#64748b")

    box(draw, (540, 150, 1060, 370), "LLM 代码分析", [
        "标准化片段 + 条件 + 历史包",
        "prediction / locations / data_flow",
        "POC 草案 + 成功标准",
        "fixed prompt: final-wp4-v2",
    ], "#dbeafe", "#2563eb")

    box(draw, (1130, 150, 1800, 370), "传统扫描器", [
        "Burp Pro：crawl + audit（XML）",
        "AWVS：REST API /targets → /scans",
        "Wapiti 3.0.4：本机参考实现（JSON）",
        "认证 / 并发 / 速率 / scope 固定",
    ], "#dcfce7", "#16a34a")

    # Scope -> LLM
    arrow(draw, (470, 250), (540, 250), "#64748b")
    # Flow 1 and 2 between LLM and scanner (short gap, numbered)
    arrow(draw, (1060, 235), (1130, 235), "#2563eb", "1")
    arrow(draw, (1130, 330), (1060, 330), "#16a34a", "2")

    box(draw, (60, 430, 470, 620), "证据库", [
        "verification/evidence/<run_id>",
        "optional2/scanner_raw",
        "optional2/case_studies",
        "脱敏 / 哈希 / 只追加",
    ], "#e2e8f0", "#64748b")

    box(draw, (540, 430, 1060, 650), "LLM 解释与扩展", [
        "代码根因 / 数据流 / 前提",
        "确认 / 排除 / 范围外",
        "生成复扫请求或补充测试",
        "llm_assessment/*.json",
    ], "#dbeafe", "#2563eb")

    box(draw, (1130, 430, 1800, 620), "扫描原始输出", [
        "Burp XML：issue / request",
        "AWVS JSON：vulnerabilities",
        "Wapiti JSON：request / payload",
        "只读保存，不手工改证据",
    ], "#fef3c7", "#d97706")

    arrow(draw, (470, 520), (540, 520), "#64748b")
    arrow(draw, (1130, 500), (1060, 500), "#d97706", "3")
    arrow(draw, (1060, 590), (1130, 590), "#2563eb", "4")

    box(draw, (400, 730, 1450, 860), "归一化与去重", [
        "字段：asset / route / method / parameter / vuln_type / condition",
        "去重键：asset + route + method + parameter + vuln_type + condition",
        "来源：llm / scanner:wapiti / scanner:burp / scanner:awvs；不同角色/配置/阶段不合并",
    ], "#ede9fe", "#7c3aed")
    arrow(draw, (800, 650), (800, 730), "#7c3aed", "5")

    box(draw, (280, 930, 660, 1080), "merged_findings.csv", [
        "来源 + 唯一键 + 状态",
        "证据 / 请求样例 / 代码位置",
        "确认 / 排除 / 未测 分开",
    ], "#ffe4e6", "#e11d48")

    box(draw, (720, 930, 1100, 1080), "POC / 人工复核", [
        "无害 POC / 浏览器 / DB 回查",
        "独立回查 + 恢复",
        "200/反射/ok 不算确认",
    ], "#ffedd5", "#ea580c")

    box(draw, (1160, 930, 1540, 1080), "比较报告", [
        "覆盖率 / 互补率",
        "告警有效率 / 人工耗时",
        "四象限 / limitations",
    ], "#cffafe", "#0891b2")

    arrow(draw, (470, 860), (470, 930), "#7c3aed")
    arrow(draw, (660, 1000), (720, 1000), "#e11d48")
    arrow(draw, (1100, 1000), (1160, 1000), "#ea580c")

    # Legend
    draw.rounded_rectangle((60, 1095, 1540, 1145), radius=10, fill="#ffffff", outline="#cbd5e1")
    draw.text((78, 1105), "① LLM 候选 → 工具复扫     ② 工具告警 → LLM 解释/扩展     ③ 扫描器原始结果进入分析     "
                           "④ 复扫/补测请求回送扫描器    ⑤ 统一 schema 后去重合并",
              font=font(17), fill=MUTED)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
