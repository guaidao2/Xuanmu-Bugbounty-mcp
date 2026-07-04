"""Host 头注入检测工具"""

from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url, parse_url


async def bb_host_inject(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    Host 头注入检测 — 密码重置投毒/Web 缓存污染

    检测:
    1. Host 头覆盖
    2. X-Forwarded-Host 注入
    3. X-Forwarded-For + Host 组合
    4. 重复 Host 头

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        Host 头注入检测结果
    """
    url = normalize_url(url)
    parsed = parse_url(url)
    original_host = parsed["host"]

    results = []
    results.append(f"[*] Host 头注入检测目标: {url}")
    results.append(f"[*] 原始 Host: {original_host}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    # 测试场景
    test_cases = [
        {"name": "Host 覆盖", "headers": {"Host": "evil.com"}},
        {"name": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": "evil.com"}},
        {"name": "X-Host", "headers": {"X-Host": "evil.com"}},
        {"name": "X-Forwarded-Server", "headers": {"X-Forwarded-Server": "evil.com"}},
        {"name": "X-HTTP-Host-Override", "headers": {"X-HTTP-Host-Override": "evil.com"}},
        {"name": "Forwarded", "headers": {"Forwarded": "host=evil.com"}},
        {"name": "重复 Host", "headers": {"Host": f"{original_host},evil.com"}},
        {"name": "Host + XFH 组合", "headers": {
            "Host": original_host,
            "X-Forwarded-Host": "evil.com",
        }},
        {"name": "Tab 注入 Host", "headers": {"Host": f"evil.com\t{original_host}"}},
    ]

    findings = []

    for case in test_cases:
        try:
            resp = await client.get(url, headers=case["headers"])
            body = resp.text
            status = resp.status_code

            indicators = []
            # 检查 evil.com 是否被反射到响应中
            if "evil" in body.lower():
                # 找出包含 evil.com 的上下文
                import re
                matches = re.findall(r'[^.]*evil\.com[^.]*\.?', body, re.IGNORECASE)
                if matches:
                    indicators.append("evil.com 被反射到响应中")
                    for m in matches[:3]:
                        indicators.append(f"  → {m.strip()[:120]}")

            # 检查 Location 头
            location = resp.headers.get("Location", "")
            if "evil.com" in location.lower():
                indicators.append(f"Location 头被劫持: {location}")

            # 检查是否有其他引用
            for key, val in resp.headers.items():
                if "evil.com" in val.lower():
                    indicators.append(f"{key}: {val[:100]}")

            if indicators:
                findings.append({
                    "case": case["name"],
                    "status": status,
                    "indicators": indicators,
                })
        except Exception as e:
            findings.append({
                "case": case["name"],
                "status": 0,
                "indicators": [f"请求失败: {str(e)[:60]}"],
            })

    if findings:
        results.append(f"[!] 发现 {len(findings)} 个 Host 头注入风险:")
        results.append("")
        for f in findings:
            results.append(f"  [{f['status']}] {f['case']}")
            for ind in f["indicators"]:
                results.append(f"    → {ind}")
            results.append("")
    else:
        results.append("[-] 未检测到 Host 头注入风险")
        results.append("")

    results.append("[*] Host 头注入漏洞可能的影响:")
    results.append("  🔹 密码重置投毒 — 用户收到的重置链接指向攻击者域名")
    results.append("  🔹 Web 缓存污染 — 将恶意内容缓存到 CDN")
    results.append("  🔹 虚拟主机绕过 — 访问预期的其他虚拟站点")
    results.append("")
    results.append("[*] 手动验证:")
    results.append("  curl -H 'Host: evil.com' {url}")
    results.append("  curl -H 'X-Forwarded-Host: evil.com' {url}")

    return "\n".join(results)
