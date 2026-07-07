"""指纹导入工具 — 从 FingerprintHub / EHole 下载并转换为增强指纹格式

用法:
    python -m xuanmu_bb.tools.fingerprint_importer

这会将 FingerprintHub 的指纹转换并合并到 data/fingerprints_hub.py 中。
"""

import json
import re
import os
import urllib.request
from typing import List, Dict, Any

FINGERPRINT_HUB_URL = "https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint_v3.json"
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "fingerprints_hub.py")

# 技术名称 -> 分类映射（基于常见模式）
NAME_CATEGORY_MAP = {
    "cms": 1, "blog": 3, "wordpress": 1, "drupal": 1, "joomla": 1,
    "oa": 4, "办公": 4, "协同": 4, "泛微": 4, "致远": 4, "通达": 4, "蓝凌": 4,
    "erp": 5, "财务": 5, "用友": 5, "金蝶": 5,
    "waf": 9, "防火墙": 9, "安全狗": 9, "云锁": 9, "堡垒机": 9, "vpn": 14,
    "邮件": 13, "mail": 13, "email": 13, "coremail": 13,
    "监控": 12, "视频": 17, "摄像头": 17, "hikvision": 17, "海康": 17, "大华": 17, "dvr": 17, "nvr": 17,
    "路由器": 11, "交换机": 11, "网关": 11, "huawei": 11, "h3c": 11, "cisco": 11,
    "nas": 23, "群晖": 23, "synology": 23,
    "devops": 20, "jenkins": 20, "gitlab": 20, "grafana": 20, "kibana": 20,
    "cdn": 8, "cloudflare": 8,
}


def guess_category(name: str) -> List[int]:
    """根据名称猜测技术分类。"""
    name_lower = name.lower()
    for keyword, cat_id in NAME_CATEGORY_MAP.items():
        if keyword in name_lower:
            return [cat_id]
    return []


def convert_fingerprinthub_entry(entry: dict) -> dict:
    """将 FingerprintHub 格式转为增强指纹格式。"""
    name = entry.get("name", "Unknown")
    keywords = entry.get("keyword", [])
    favicon_hashes = entry.get("favicon_hash", [])
    headers_match = entry.get("headers", {})
    status_code = entry.get("status_code", 0)
    path = entry.get("path", "/")
    priority = entry.get("priority", 3)

    if not keywords and not favicon_hashes and not headers_match:
        return None

    cats = guess_category(name)
    confidence = "高" if priority <= 1 else "中" if priority <= 2 else "低"

    result = {
        "name": name,
        "cats": cats,
        "confidence": confidence,
    }

    # 多个 keyword 数组是 OR 关系（不同指纹条目），每个数组内的关键词是 AND 关系
    if favicon_hashes:
        # 优先用 favicon
        result["method"] = "favicon"
        try:
            result["favicon_hash"] = int(favicon_hashes[0])
        except (ValueError, TypeError):
            result["favicon_hash"] = favicon_hashes[0]
    elif keywords:
        # keyword_and 模式
        result["method"] = "keyword_and"
        result["location"] = "body"
        result["keywords"] = keywords
    elif headers_match:
        result["method"] = "score"
        signals = []
        for hdr, value in headers_match.items():
            if value:
                signals.append({"hdr": hdr, "pat": re.escape(value), "w": 60})
            else:
                signals.append({"hdr": hdr, "pat": r".+", "w": 40})
        result["signals"] = signals

    if status_code and status_code != 0:
        result["status_code"] = status_code

    if path and path != "/":
        result["path"] = path

    return result


def download_fingerprinthub() -> List[dict]:
    """下载 FingerprintHub 指纹数据。"""
    print(f"[*] 下载 FingerprintHub: {FINGERPRINT_HUB_URL}")
    try:
        req = urllib.request.Request(FINGERPRINT_HUB_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        print(f"[+] 下载成功: {len(data)} 条指纹")
        return data
    except Exception as e:
        print(f"[!] 下载失败: {e}")
        return []


def convert_and_save(raw_entries: List[dict], output_path: str, max_entries: int = 500):
    """转换并保存为 Python 文件。"""
    converted = []
    seen_names = set()
    favicon_count = 0

    for entry in raw_entries:
        result = convert_fingerprinthub_entry(entry)
        if result is None:
            continue
        name = result["name"]
        # 对同名指纹，优先保留 favicon 版本的
        if name in seen_names:
            existing = next((c for c in converted if c["name"] == name), None)
            if existing and result.get("method") == "favicon":
                converted.remove(existing)
                converted.append(result)
                favicon_count += 1
            continue
        seen_names.add(name)
        if result.get("method") == "favicon":
            favicon_count += 1
        converted.append(result)
        if len(converted) >= max_entries:
            break

    # 按名称排序
    converted.sort(key=lambda x: x["name"])

    # 生成 Python 文件
    lines = [
        '"""从 FingerprintHub 导入的指纹库 — 自动生成',
        f"",
        f"条目数: {len(converted)}",
        f"Favicon 哈希: {favicon_count}",
        f"来源: {FINGERPRINT_HUB_URL}",
        '"""',
        "",
    ]

    # 用紧凑格式写入
    entries_json = json.dumps(converted, ensure_ascii=False, indent=2)
    lines.append(f"HUB_FINGERPRINTS = {entries_json}")
    lines.append("")

    # 生成 favicon 映射
    favicon_lines = ["# Favicon hash -> name 快速查找"]
    favicon_lines.append("HUB_FAVICON_MAP = {")
    for c in converted:
        if c.get("method") == "favicon":
            h = c["favicon_hash"]
            if isinstance(h, int):
                favicon_lines.append(f"    {h}: \"{c['name']}\",")
    favicon_lines.append("}")
    lines.extend(favicon_lines)
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] 已保存 {len(converted)} 条指纹到 {output_path}")
    print(f"    其中 Favicon 哈希: {favicon_count}")
    print(f"    Keyword AND: {sum(1 for c in converted if c.get('method') == 'keyword_and')}")
    print(f"    Score-based: {sum(1 for c in converted if c.get('method') == 'score')}")

    return converted


def main():
    """主入口。"""
    print("=" * 50)
    print("Xuanmu Bug Bounty — FingerprintHub 导入工具")
    print("=" * 50)
    print()

    raw = download_fingerprinthub()
    if not raw:
        print("[!] 无法获取指纹数据，请检查网络连接")
        return 1

    convert_and_save(raw, OUTPUT_FILE, max_entries=300)
    print()
    print("[*] 完成后请在 fingerprint.py 中导入:")
    print("    from xuanmu_bb.data.fingerprints_hub import HUB_FINGERPRINTS, HUB_FAVICON_MAP")
    return 0


if __name__ == "__main__":
    exit(main())
