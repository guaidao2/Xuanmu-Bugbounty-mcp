"""Web 指纹识别工具"""

import re
from typing import Optional

from ..client import HttpClient
from ..data import FINGERPRINTS, WAF_SIGNATURES
from ..utils import normalize_url, extract_title


async def bb_fingerprint(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    Web 指纹识别 — 检测技术栈、CMS、WAF

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        识别的技术栈、CMS、WAF 信息
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.get(url)
        headers = dict(resp.headers)
        body = resp.text
        status = resp.status_code

        results.append(f"[*] HTTP 状态码: {status}")
        results.append(f"[*] 页面标题: {extract_title(body)}")
        results.append(f"[*] 响应大小: {len(body):,} bytes")

        # ---- Server 头 ----
        server = headers.get("Server", "N/A")
        x_powered = headers.get("X-Powered-By", "")
        results.append(f"[*] Server: {server}")
        if x_powered:
            results.append(f"[*] X-Powered-By: {x_powered}")
        results.append("")

        # ---- 指纹匹配 ----
        detected = []
        for fp in FINGERPRINTS:
            matched = False
            # 检查 header 匹配
            for hdr, pattern in fp.get("headers", {}).items():
                val = headers.get(hdr, "")
                if re.search(pattern, val, re.IGNORECASE):
                    matched = True
                    break
            # 检查 body 匹配
            body_pattern = fp.get("body", "")
            if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
                matched = True
            if matched:
                detected.append(fp["name"])

        if detected:
            results.append(f"[✓] 识别到 {len(detected)} 项指纹:")
            for name in detected:
                results.append(f"  └─ {name}")
        else:
            results.append("[-] 未识别到已知指纹")

        # ---- WAF 检测 ----
        results.append("")
        waf_detected = []
        for waf in WAF_SIGNATURES:
            matched = False
            for hdr, pattern in waf.get("headers", {}).items():
                val = headers.get(hdr, "")
                if re.search(pattern, val, re.IGNORECASE):
                    matched = True
                    break
            body_pattern = waf.get("body", "")
            if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
                matched = True
            if matched:
                waf_detected.append(waf["name"])

        if waf_detected:
            results.append(f"[!] WAF 检测: 发现 {', '.join(waf_detected)}")
            results.append("  └─ 后续测试建议注意绕过")

            # WAF 绕过建议
            bypass_hints = {
                "Cloudflare": "尝试直接访问源站 IP，或使用特殊 UA/Headers",
                "阿里云 WAF": "尝试编码绕过、分块传输、HTTP 参数污染",
                "腾讯云 WAF": "尝试大小写混淆、双重 URL 编码",
                "安全狗": "尝试换行绕过、注释混淆",
                "ModSecurity": "尝试 CRLF 注入、协议违规绕过",
                "长亭 SafeLine": "尝试请求方法转换、参数变异",
            }
            for waf_name in waf_detected:
                hint = bypass_hints.get(waf_name)
                if hint:
                    results.append(f"    {waf_name} 绕过: {hint}")
        else:
            results.append("[*] WAF: 未检测到已知 WAF")

        # ---- 关键配置信息 ----
        results.append("")
        results.append("[*] 关键响应头:")
        important_headers = [
            "Set-Cookie", "X-Frame-Options", "X-Content-Type-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "Access-Control-Allow-Origin", "Location",
        ]
        for h in important_headers:
            if h in headers:
                results.append(f"  {h}: {headers[h][:200]}")

    except Exception as e:
        results.append(f"[!] 指纹识别失败: {e}")

    return "\n".join(results)
