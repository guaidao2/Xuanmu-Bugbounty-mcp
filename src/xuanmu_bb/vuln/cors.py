"""CORS 跨域检测工具"""

from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


# 测试用 Origin 列表
TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://{target}.evil.com",
    "https://evil{target}.com",
    "https://{target}%2eevil.com",
    "https://{target}e.com",
    "https://evil{target}",
    "http://evil.com",
    "https://evil.com:443",
    "https://evil.com.evildomain.com",
    "https://evil.com/@{target}",
    "https://evil.com#@{target}",
]


async def bb_cors(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 10,
) -> str:
    """
    CORS 跨域检测 — Origin 反射/凭据配置检查

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 10）

    Returns:
        CORS 配置分析结果
    """
    url = normalize_url(url)
    from urllib.parse import urlparse
    target_host = urlparse(url).hostname or ""

    results = []
    results.append(f"[*] CORS 检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # 1. 先发一个不带 Origin 的 OPTIONS 请求
    try:
        resp = await client.options(url)
        cors_headers = {
            "Access-Control-Allow-Origin": resp.headers.get("Access-Control-Allow-Origin", ""),
            "Access-Control-Allow-Credentials": resp.headers.get("Access-Control-Allow-Credentials", ""),
            "Access-Control-Allow-Methods": resp.headers.get("Access-Control-Allow-Methods", ""),
            "Access-Control-Allow-Headers": resp.headers.get("Access-Control-Allow-Headers", ""),
            "Access-Control-Expose-Headers": resp.headers.get("Access-Control-Expose-Headers", ""),
            "Access-Control-Max-Age": resp.headers.get("Access-Control-Max-Age", ""),
        }
        has_cors = any(v for v in cors_headers.values() if v)
        if has_cors:
            results.append("[✓] 服务器返回了 CORS 头:")
            for k, v in cors_headers.items():
                if v:
                    results.append(f"  {k}: {v}")
            results.append("")
    except Exception:
        pass

    # 2. 测试各种 Origin
    results.append("[*] Origin 反射测试:")
    results.append("")

    findings = []
    # 先发一个不带 Origin 的基准请求
    try:
        base_resp = await client.get(url)
        base_allow_origin = base_resp.headers.get("Access-Control-Allow-Origin", "")
    except Exception:
        base_allow_origin = ""

    for origin_tpl in TEST_ORIGINS:
        origin = origin_tpl.replace("{target}", target_host)
        try:
            resp = await client.get(url, headers={"Origin": origin})
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")

            if allow_origin:
                if allow_origin == "*":
                    findings.append({
                        "origin": origin,
                        "allow_origin": "*",
                        "credentials": allow_creds,
                        "severity": "HIGH",
                        "note": "通配符 Origin，任何网站可跨域读取",
                    })
                elif allow_origin == origin or origin.lower() in allow_origin.lower():
                    cred_note = "，支持凭据(Credentials=true)" if allow_creds.lower() == "true" else ""
                    findings.append({
                        "origin": origin,
                        "allow_origin": allow_origin,
                        "credentials": allow_creds,
                        "severity": "MEDIUM" if allow_creds.lower() == "true" else "LOW",
                        "note": f"Origin 被反射回显{cred_note}",
                    })
        except Exception:
            pass

    if findings:
        results.append(f"[!] 发现 {len(findings)} 个 CORS 配置问题:")
        results.append("")
        for f in findings:
            severity_tag = {"HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(f["severity"], "?")
            results.append(f"  {severity_tag} [{f['severity']}] Origin: {f['origin']}")
            results.append(f"      Allow-Origin: {f['allow_origin']}")
            results.append(f"      Credentials: {f['credentials'] or '(无)'}")
            results.append(f"      {f['note']}")
            results.append("")
    else:
        results.append("[-] 未发现 Origin 反射")
        results.append("")

    # 3. 总结
    results.append("[*] 安全建议:")
    results.append("  ✅ 避免使用 Access-Control-Allow-Origin: *")
    results.append("  ✅ 避免反射 Origin 头")
    results.append("  ✅ 敏感接口应限制特定 Origin")
    results.append("  ✅ Access-Control-Allow-Credentials: true 需要搭配特定 Origin")

    return "\n".join(results)
