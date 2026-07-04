"""WAF 指纹识别工具 — 独立检测 + 绕过建议"""

from typing import Optional

from ..data.waf import detect_waf, WAF_RULES


async def bb_waf_check(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    WAF 指纹识别 — 检测 WAF 类型 + 绕过建议 + 推荐设置

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        WAF 检测结果 + 绕过建议 + 推荐扫描参数
    """
    result = []
    result.append(f"[*] WAF 检测目标: {url}")
    result.append("")

    waf = await detect_waf(url, proxy=proxy, cookie=cookie, auth_token=auth_token, timeout=timeout)

    if waf["detected"]:
        result.append(f"[!] 检测到 WAF: {waf['name']} (置信度: {waf['confidence']})")
        if waf.get("raw"):
            raw = waf["raw"]
            result.append(f"    状态码: {raw.get('status', 'N/A')}")
            result.append(f"    Server: {raw.get('server', 'N/A')}")
            if raw.get("cf_ray"):
                result.append(f"    CF-RAY: {raw['cf_ray']}")
        result.append("")
        result.append("[绕过建议]:")
        for i, tip in enumerate(waf.get("bypass", []), 1):
            result.append(f"  {i}. {tip}")
        result.append("")
        result.append("[推荐扫描设置]:")
        result.append("  waf_mode=safe      → 自动降速 + 轮换 UA")
        result.append("  request_delay=3    → 请求间隔 3 秒")
        result.append("  max_retries=3      → 拦截后重试 3 次")
    else:
        result.append("[✓] 未检测到已知 WAF")
        result.append("")
        result.append("[推荐扫描设置]:")
        result.append("  waf_mode=off       → 不启用 WAF 防护")
        result.append("  request_delay=0.5  → 默认请求间隔")

    result.append("")
    result.append("[已知 WAF 列表]:")
    for w in WAF_RULES:
        result.append(f"  └─ {w['name']}")

    return "\n".join(result)
