"""IDOR 越权检测工具 — 双Token/双Cookie 对比 + 序号枚举"""

import json
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_idor(
    url: str,
    token_owner: str = "",
    token_attacker: str = "",
    cookie_owner: str = "",
    cookie_attacker: str = "",
    method: str = "GET",
    param: str = "",
    range_start: int = 1,
    range_end: int = 10,
    proxy: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    IDOR 越权检测 — 双Token / 双Cookie 对比 + 序号枚举

    支持两种认证方式:
    - Bearer Token 对比（JWT/OAuth API）
    - Session Cookie 对比（PHP/Java/.NET 等 Web 应用）

    可以单独用其中一种，也可以同时用两种。

    Args:
        url: 目标 URL，如 https://target.com/profile
        token_owner: 资源拥有者的 Bearer Token（可选）
        token_attacker: 攻击者的 Bearer Token（可选）
        cookie_owner: 资源拥有者的 Session Cookie（可选）
        cookie_attacker: 攻击者的 Session Cookie（可选）
        method: 请求方法（GET/POST/PUT/DELETE）
        param: URL 参数名，用于序号枚举
        range_start: 序号枚举起始值（默认 1）
        range_end: 序号枚举结束值（默认 10）
        proxy: 代理地址（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        IDOR 检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] IDOR 越权检测目标: {url}")
    results.append("")

    findings = []

    # 判断使用的认证方式
    use_token = bool(token_owner and token_attacker)
    use_cookie = bool(cookie_owner and cookie_attacker)

    if not use_token and not use_cookie:
        results.append("[!] 请至少提供一组认证凭据:")
        results.append("  token_owner + token_attacker   (Bearer Token 对比)")
        results.append("  cookie_owner + cookie_attacker (Session Cookie 对比)")
        return "\n".join(results)

    # ============================================================
    # 认证方式 1: Bearer Token 对比
    # ============================================================
    if use_token:
        results.append("=" * 50)
        results.append("[*] Bearer Token 对比测试")
        results.append("=" * 50)
        results.append("")

        client_o = HttpClient(timeout=timeout, proxy=proxy, auth_token=token_owner)
        client_a = HttpClient(timeout=timeout, proxy=proxy, auth_token=token_attacker)

        try:
            resp_o = await client_o.request(method, url)
            resp_a = await client_a.request(method, url)

            _compare_responses(resp_o, resp_a, "Token", token_attacker, findings, results, url)
        except Exception as e:
            results.append(f"  [!] 请求异常: {e}")
        results.append("")

    # ============================================================
    # 认证方式 2: Session Cookie 对比
    # ============================================================
    if use_cookie:
        results.append("=" * 50)
        results.append("[*] Session Cookie 对比测试")
        results.append("=" * 50)
        results.append("")

        client_o = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie_owner)
        client_a = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie_attacker)

        try:
            resp_o = await client_o.request(method, url)
            resp_a = await client_a.request(method, url)

            _compare_responses(resp_o, resp_a, "Cookie", cookie_attacker[:30], findings, results, url)
        except Exception as e:
            results.append(f"  [!] 请求异常: {e}")
        results.append("")

    # ============================================================
    # 序号枚举测试（用 attacker 身份）
    # ============================================================
    if param:
        client_a = None
        if use_cookie:
            client_a = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie_attacker)
        elif use_token:
            client_a = HttpClient(timeout=timeout, proxy=proxy, auth_token=token_attacker)

        if client_a:
            results.append("=" * 50)
            results.append(f"[*] 序号枚举测试 ({param}, {range_start}-{range_end})")
            results.append("=" * 50)
            results.append("")

            import re
            for i in range(range_start, range_end + 1):
                test_url = re.sub(rf'({param}/?)(\d+)', rf'\g<1>{i}', url)
                if test_url == url:
                    sep = "&" if "?" in url else "/"
                    test_url = f"{url}{sep}{param}={i}"
                try:
                    resp = await client_a.request(method, test_url)
                    if resp.status_code == 200:
                        findings.append({
                            "type": "序号枚举越权",
                            "detail": f"Attacker 可访问 {test_url} (HTTP 200)",
                            "severity": "MEDIUM",
                            "poc": test_url,
                        })
                except Exception:
                    pass
            results.append("")

    # ============================================================
    # 输出结果
    # ============================================================
    if not findings:
        results.append("[-] 未检测到 IDOR 越权漏洞")
    else:
        results.append("=" * 50)
        results.append(f"[!] 发现 {len(findings)} 个越权风险:")
        results.append("")
        for f in findings:
            sev = {"HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(f["severity"], "?")
            results.append(f"  {sev} [{f['severity']}] {f['type']}")
            results.append(f"      {f['detail']}")
            if f.get("poc"):
                results.append(f"      PoC: {f['poc']}")
            results.append("")

    results.append("[*] 手动验证建议:")
    results.append("  用两个浏览器的无痕窗口分别登录不同账号")
    results.append("  对比同一接口的返回数据差异")
    results.append("  重点关注: /api/users/, /api/orders/, /api/profile/")

    return "\n".join(results)


def _compare_responses(resp_o, resp_a, auth_type, attacker_cred, findings, results, url):
    """对比 owner 和 attacker 的响应"""
    status_o, body_o = resp_o.status_code, resp_o.text
    status_a, body_a = resp_a.status_code, resp_a.text
    len_o, len_a = len(body_o), len(body_a)

    results.append(f"  [Owner]    HTTP {status_o} ({len_o:,} bytes)")
    results.append(f"  [Attacker] HTTP {status_a} ({len_a:,} bytes)")

    # Cookie 是否随请求变化
    set_cookie_o = resp_o.headers.get("Set-Cookie", "")
    set_cookie_a = resp_a.headers.get("Set-Cookie", "")
    if set_cookie_o != set_cookie_a and set_cookie_o and set_cookie_a:
        results.append(f"  [*] Cookie 刷新: Owner/Attacker 收到不同的 Set-Cookie")

    # 两者都 200 → 可能越权
    if status_o == 200 and status_a == 200:
        # 计算内容相似度
        words_o = set(body_o.strip()[:500].split())
        words_a = set(body_a.strip()[:500].split())
        union = words_o | words_a
        intersection = words_o & words_a
        similarity = len(intersection) / max(len(union), 1)

        if similarity > 0.5:
            findings.append({
                "type": f"水平越权 (via {auth_type})",
                "detail": f"Owner 和 Attacker 都返回 HTTP 200，内容相似度 {similarity:.0%}",
                "severity": "HIGH",
                "poc": f"{auth_type}: {attacker_cred}... → {url}",
            })
        else:
            results.append(f"  [*] Attacker 内容与 Owner 不同（相似度 {similarity:.0%}），可能已鉴权")

    elif status_o == 200 and status_a in (401, 403):
        results.append(f"  [✓] 鉴权正常: Attacker 被拒绝 (HTTP {status_a})")

    elif status_o != status_a:
        results.append(f"  [*] Owner={status_o}, Attacker={status_a}")
