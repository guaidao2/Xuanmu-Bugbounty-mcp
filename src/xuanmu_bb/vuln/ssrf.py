"""SSRF 检测 — 结构化输出 + 二次确认"""

from typing import Optional

from ..client import HttpClient
from ..data import SSRF_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


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
    custom_payloads: str = "",
) -> dict:
    """SSRF 检测 — 内网地址探测 + 协议转换。

    Args:
        custom_payloads: 自定义 SSRF URL（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_ssrf", url)

    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    # custom_payloads 是 URL 字符串列表
    ssrf_urls = list(SSRF_PAYLOADS)
    if custom_payloads:
        ssrf_urls.extend([p.strip() for p in custom_payloads.split(",") if p.strip()])
    rb.data["metadata"]["payload_count"] = len(ssrf_urls)

    test_params = extract_params_from_url(url, params)
    if not test_params:
        rb.add_suggestion("未找到参数")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    try:
        base_resp = await client.get(url)
        rb.inc_requests()
        auth_status = "required" if base_resp.status_code in (401, 403) else "none"
        rb.data["metadata"]["auth_status"] = auth_status
    except Exception:
        base_resp = None

    findings = []

    for param in test_params:
        for ssrf_url in ssrf_urls:
            try:
                new_url = build_url_with_param(url, param, ssrf_url)
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: ssrf_url})
                else:
                    resp = await client.get(new_url)
                rb.inc_requests()
                resp_body = resp.text.lower()

                evidence = ""
                severity = "INFO"

                if "meta-data" in resp_body and "ami" in resp_body:
                    evidence = "云元数据泄露（AWS IMDSv1）"
                    severity = "CRITICAL"
                elif "passwd" in resp_body and "root:" in resp_body:
                    evidence = "文件读取成功 (/etc/passwd)"
                    severity = "CRITICAL"
                elif "[fonts]" in resp_body or "for 16-bit" in resp_body:
                    evidence = "Windows 文件读取 (win.ini)"
                    severity = "HIGH"
                elif base_resp and abs(len(resp.content) - len(base_resp.content)) > 1000:
                    evidence = f"响应大小显著变化 ({len(base_resp.content)} -> {len(resp.content)})"
                    severity = "MEDIUM"

                if evidence:
                    finding = {
                        "param": param, "ssrf_url": ssrf_url,
                        "severity": severity, "evidence": evidence,
                        "status_code": resp.status_code, "verified": False,
                    }
                    # 二次确认：用不同内网地址验证
                    if severity in ("CRITICAL", "HIGH"):
                        finding["verified"] = True
                        finding["verified_by"] = "响应中包含明确的系统文件/元数据内容，无需二次确认"
                    elif severity == "MEDIUM":
                        verify_url = ssrf_url.replace("127.0.0.1", "localhost").replace("localhost", "127.0.0.1")
                        if verify_url != ssrf_url:
                            try:
                                vurl = build_url_with_param(url, param, verify_url)
                                if method.upper() == "POST":
                                    vresp = await client.post(url, data=body or {param: verify_url})
                                else:
                                    vresp = await client.get(vurl)
                                rb.inc_requests()
                                if base_resp and abs(len(vresp.content) - len(base_resp.content)) > 1000:
                                    finding["verified"] = True
                                    finding["verified_by"] = f"二次确认: {verify_url} 同样触发响应变化"
                                    finding["severity"] = "HIGH"
                            except Exception:
                                pass
                    findings.append(finding)

            except Exception:
                pass

    for f in findings:
        rb.add_finding(f)

    if not findings:
        rb.add_suggestion("无回显 SSRF 可使用 OOB（外带）方式验证，将 SSRF URL 指向 Collaborator / interactsh")

    return rb.finalize()
