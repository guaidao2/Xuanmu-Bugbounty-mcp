"""SSRF 检测工具"""

import time
from typing import Optional

from ..client import HttpClient
from ..data import SSRF_PAYLOADS
from ..utils import normalize_url, extract_params_from_url, build_url_with_param, run_waf_precheck


async def bb_ssrf(
    url: str,
    params: str = "",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 10,
    waf_mode: str = "safe",
    max_retries_on_block: int = 3,
    request_delay: float = 0.5,
    method: str = "GET",
    body: str = "",
) -> str:
    """
    SSRF 检测 — 内网地址探测 + 协议转换

    Args:
        url: 目标 URL（含参数）
        params: 参数字段名（逗号分隔）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 10）

    Returns:
        SSRF 检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] SSRF 检测目标: {url}")
    results.append(f"[*] Payload 数: {len(SSRF_PAYLOADS)}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # WAF 预检（使用公共函数）
    waf_lines = await run_waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay,
                                       proxy=proxy, cookie=cookie, auth_token=auth_token)
    results.extend(waf_lines)

    test_params = extract_params_from_url(url, params)

    if not test_params:
        results.append("[!] 未找到参数")
        return "\n".join(results)

    # 基线
    try:
        base_resp = await client.get(url)
        error_keywords = ["error", "exception", "timeout", "refused", "failed"]
        base_errors = sum(1 for kw in error_keywords if kw in base_resp.text.lower())
        auth_status = "required" if base_resp.status_code in (401, 403) else "none"
        results.append(f"[AUTH: {auth_status}] HTTP {base_resp.status_code}")
    except Exception:
        base_errors = 0
        base_resp = None
        results.append("[AUTH: unknown] 基线请求失败")

    findings = []

    for param in test_params:
        for ssrf_url in SSRF_PAYLOADS:
            try:
                new_url = build_url_with_param(url, param, ssrf_url)
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: ssrf_url})
                else:
                    resp = await client.get(new_url)
                resp_body = resp.text.lower()

                # 检测回显内容变化
                indicators = []

                # 检查是否返回了内网页面特征
                if "meta-data" in resp_body and "ami" in resp_body:
                    indicators.append("云元数据泄露（AWS）")
                if "passwd" in resp_body and "root:" in resp_body:
                    indicators.append("文件读取成功 (/etc/passwd)")
                if "[fonts]" in resp_body or "for 16-bit app support" in resp_body:
                    indicators.append("Windows 文件读取 (win.ini)")

                # 响应大小显著变化
                if base_resp:
                    len_diff = abs(len(resp.content) - len(base_resp.content))
                    if len_diff > 1000:
                        indicators.append(f"响应大小显著变化 ({len(base_resp.content)} -> {len(resp.content)})")

                if indicators:
                    findings.append({
                        "param": param,
                        "ssrf_url": ssrf_url,
                        "indicators": indicators,
                        "status": resp.status_code,
                    })

            except Exception:
                pass

    if not findings:
        results.append("[-] 未检测到 SSRF")
        results.append("")
        results.append("[*] 提示: 无回显 SSRF 可使用 OOB（外带）方式验证")
        results.append("    将 SSRF URL 指向你的 Collaborator / Burpcollaborator / interactsh")
    else:
        results.append(f"[!] 发现 {len(findings)} 个可疑 SSRF 点:")
        results.append("")
        for f in findings:
            results.append(f"  参数: {f['param']}")
            results.append(f"  SSRF URL: {f['ssrf_url']}")
            results.append(f"  状态码: {f['status']}")
            results.append(f"  指标: {'; '.join(f['indicators'])}")
            results.append("")

    return "\n".join(results)
