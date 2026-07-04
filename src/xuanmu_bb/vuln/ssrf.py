"""SSRF 检测工具"""

from typing import Optional

from ..client import HttpClient
from ..data import SSRF_PAYLOADS
from ..utils import normalize_url
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


async def bb_ssrf(
    url: str,
    params: str = "",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 10,
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

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())

    if not test_params:
        results.append("[!] 未找到参数")
        return "\n".join(results)

    # 基线
    try:
        base_resp = await client.get(url)
        error_keywords = ["error", "exception", "timeout", "refused", "failed"]
        base_errors = sum(1 for kw in error_keywords if kw in base_resp.text.lower())
    except Exception:
        base_errors = 0
        base_resp = None

    findings = []

    for param in test_params:
        for ssrf_url in SSRF_PAYLOADS:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [ssrf_url]
                new_qs = urlencode(qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_qs))
                resp = await client.get(new_url)
                body = resp.text.lower()

                # 检测回显内容变化
                indicators = []

                # 检查是否返回了内网页面特征
                if "meta-data" in body and "ami" in body:
                    indicators.append("云元数据泄露（AWS）")
                if "passwd" in body and "root:" in body:
                    indicators.append("文件读取成功 (/etc/passwd)")
                if "[fonts]" in body or "for 16-bit app support" in body:
                    indicators.append("Windows 文件读取 (win.ini)")

                # 响应大小显著变化
                if base_resp:
                    len_diff = abs(len(resp.content) - len(base_resp.content))
                    if len_diff > 1000:
                        indicators.append(f"响应大小显著变化 ({len(base_resp.content)} → {len(resp.content)})")

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
        results.append("    🔗 将 SSRF URL 指向你的 Collaborator / Burpcollaborator / interactsh")
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
