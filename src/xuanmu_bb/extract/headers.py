"""安全头审计工具"""

import re
from typing import Optional

from ..client import HttpClient
from ..data import SECURITY_HEADERS
from ..utils import normalize_url


async def bb_headers(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    安全头审计 — 检查 HTTP 响应头的安全配置

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        安全头评分和改进建议
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 安全头审计目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.get(url)
        headers = dict(resp.headers)
    except Exception as e:
        return f"[!] 请求失败: {e}"

    score = 0
    max_score = len(SECURITY_HEADERS)
    details = []

    for header_name, description in SECURITY_HEADERS.items():
        if header_name == "Set-Cookie":
            # 特殊处理 — 检查 Cookie 属性
            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                has_secure = "secure" in set_cookie.lower()
                has_httponly = "httponly" in set_cookie.lower()
                has_samesite = "samesite" in set_cookie.lower()

                if has_secure and has_httponly and has_samesite:
                    score += 1
                    details.append((True, "Set-Cookie", "Secure + HttpOnly + SameSite 均已设置"))
                else:
                    missing = []
                    if not has_secure: missing.append("Secure")
                    if not has_httponly: missing.append("HttpOnly")
                    if not has_samesite: missing.append("SameSite")
                    details.append((False, "Set-Cookie", f"缺少: {', '.join(missing)}"))
            continue

        value = headers.get(header_name, "")
        if value:
            score += 1
            details.append((True, header_name, f"{description}: {value[:100]}"))
        else:
            details.append((False, header_name, f"缺失 — {description}"))

    # 评分
    percentage = int(score / max_score * 100) if max_score > 0 else 0
    grade = "A" if percentage >= 90 else "B" if percentage >= 70 else "C" if percentage >= 50 else "D" if percentage >= 30 else "F"

    results.append(f"[*] 安全头评分: {score}/{max_score} ({percentage}%) — 等级 {grade}")
    results.append("")

    if grade in ("A", "B"):
        results.append("[+] 安全配置良好")
    elif grade == "C":
        results.append("[!] 安全配置中等，建议改进")
    else:
        results.append("[!] 安全配置严重不足！")
    results.append("")

    # 详细信息
    results.append("[*] 检测详情:")
    results.append("")
    for ok, name, desc in details:
        icon = "[PASS]" if ok else "[FAIL]"
        results.append(f"  {icon} {name}")
        results.append(f"     {desc}")

    results.append("")
    results.append("[*] Server 信息:")
    results.append(f"  Server: {headers.get('Server', '未泄露')}")
    results.append(f"  X-Powered-By: {headers.get('X-Powered-By', '未泄露')}")

    # 额外信息泄露检测
    results.append("")
    results.append("[*] 信息泄露检查:")
    leak_headers = ["X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime",
                    "X-Version", "X-Generator", "X-Debug", "X-Proxy-Cache"]
    for h in leak_headers:
        if h in headers:
            results.append(f"  [!] {h}: {headers[h]}")

    if not any(h in headers for h in leak_headers):
        results.append("  [+] 未发现版本信息泄露")

    results.append("")
    results.append("[*] 推荐修复:")
    if not headers.get("Strict-Transport-Security"):
        results.append("  - 添加: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    if not headers.get("Content-Security-Policy"):
        results.append("  - 添加: Content-Security-Policy 限制资源来源")
    if not headers.get("X-Frame-Options"):
        results.append("  - 添加: X-Frame-Options: DENY 或 SAMEORIGIN")
    if not headers.get("X-Content-Type-Options"):
        results.append("  - 添加: X-Content-Type-Options: nosniff")
    if not headers.get("Referrer-Policy"):
        results.append("  - 添加: Referrer-Policy: strict-origin-when-cross-origin")

    return "\n".join(results)
