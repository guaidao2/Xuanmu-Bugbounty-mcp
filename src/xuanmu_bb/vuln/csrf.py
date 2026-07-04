"""CSRF 检测工具"""

import re
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url, extract_forms


async def bb_csrf(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    CSRF 检测 — 检查表单 Token 机制和敏感操作验证

    检测逻辑:
    1. 提取页面中的所有表单
    2. 检查是否有 CSRF Token
    3. 检查 Referer/Origin 校验
    4. 分析 Cookie SameSite 属性

    Args:
        url: 目标 URL（包含表单的页面或敏感操作接口）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        CSRF 防护分析结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] CSRF 检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    try:
        resp = await client.get(url)
        body = resp.text
        headers = dict(resp.headers)
    except Exception as e:
        return f"[!] 请求失败: {e}"

    # 1. 提取表单
    forms = extract_forms(body)
    if forms:
        results.append(f"[*] 发现 {len(forms)} 个表单:")
        results.append("")

        csrf_token_names = [
            "csrf", "_csrf", "csrf_token", "_csrf_token", "csrfmiddlewaretoken",
            "token", "_token", "authenticity_token", "xsrf", "_xsrf",
            "security_token", "csrfToken", "CSRFToken", "__RequestVerificationToken",
        ]

        for i, form in enumerate(forms):
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            results.append(f"  ── 表单 #{i+1} ──")
            results.append(f"      动作: {action}")
            results.append(f"      方法: {method}")
            results.append(f"      字段: {', '.join(inputs[:8])}{'...' if len(inputs) > 8 else ''}")

            # 检查 CSRF Token
            has_csrf = False
            for inp in inputs:
                inp_lower = inp.lower()
                for token_name in csrf_token_names:
                    if token_name in inp_lower:
                        has_csrf = True
                        results.append(f"      ✅ CSRF Token: {inp}")
                        break
                if has_csrf:
                    break

            if not has_csrf:
                results.append(f"      ❌ 未检测到 CSRF Token — 可能存在 CSRF 风险")

            # 如果是 GET 表单且无 Token，风险更高
            if method == "GET" and not has_csrf:
                results.append(f"      ⚠️  GET 表单且无 Token — 高危")
            results.append("")
    else:
        results.append("[*] 页面中未发现表单")
        results.append("")

    # 2. 检查 Cookie SameSite
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        samesite = re.search(r'SameSite=(Lax|Strict|None)', set_cookie, re.IGNORECASE)
        if samesite:
            results.append(f"[*] SameSite: {samesite.group(1)}")
            if samesite.group(1).lower() == "none":
                results.append("  ⚠️ SameSite=None — 跨站请求可携带 Cookie")
        else:
            results.append("[!] Cookie 未设置 SameSite 属性 — 默认行为因浏览器而异")
        secure = "Secure" in set_cookie
        httponly = "HttpOnly" in set_cookie
        results.append(f"  Secure: {'✅' if secure else '❌'} | HttpOnly: {'✅' if httponly else '❌'}")
    else:
        results.append("[*] 未返回 Set-Cookie")

    # 3. 检查 Referer/Origin 校验（通过自定义头测试）
    results.append("")
    results.append("[*] Referer/Origin 校验检测:")
    for test_origin in ["https://evil.com", "https://example.com"]:
        try:
            resp2 = await client.get(url, headers={
                "Origin": test_origin,
                "Referer": f"{test_origin}/page",
            })
            if resp2.status_code == 200:
                results.append(f"  Origin={test_origin} → {resp2.status_code}（可能未校验）")
            else:
                results.append(f"  Origin={test_origin} → {resp2.status_code}（可能校验了）")
        except Exception:
            pass

    # 4. 安全建议
    results.append("")
    results.append("[*] CSRF 防护建议:")
    results.append("  ✅ 使用 Anti-CSRF Token")
    results.append("  ✅ 使用 SameSite=Strict/Lax Cookie")
    results.append("  ✅ 校验 Referer/Origin 头")
    results.append("  ✅ 敏感操作使用 POST + Token")
    results.append("  ✅ 添加二次验证（密码/验证码）")

    return "\n".join(results)
