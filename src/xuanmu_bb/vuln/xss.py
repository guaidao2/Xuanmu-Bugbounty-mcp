"""XSS 检测工具 — 结构化输出 + 二次确认"""

import re
from typing import Optional

from ..client import HttpClient
from ..data import XSS_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


async def bb_xss(
    url: str,
    params: str = "",
    method: str = "GET",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
    waf_mode: str = "safe",
    max_retries_on_block: int = 3,
    request_delay: float = 0.5,
    body: str = "",
    custom_payloads: str = "",
) -> dict:
    """XSS 检测 — 反射型 XSS。

    Args:
        url: 目标 URL（含参数）
        custom_payloads: 自定义 XSS payload（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_xss", url)

    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    payloads = merge_payloads(XSS_PAYLOADS, custom_payloads, "custom")
    rb.data["metadata"]["payload_count"] = len(payloads)

    test_params = extract_params_from_url(url, params)
    if not test_params:
        rb.add_suggestion("未找到参数 — 请提供带参数的 URL 或通过 params= 指定")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    findings = []

    for param in test_params:
        for payload_entry in payloads:
            payload = payload_entry["payload"]
            ptype = payload_entry["type"]

            try:
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    new_url = build_url_with_param(url, param, payload)
                    resp = await client.get(new_url)
                rb.inc_requests()

                resp_body = resp.text

                if payload in resp_body:
                    html_encoded = False
                    encoded_versions = [
                        payload.replace("<", "&lt;").replace(">", "&gt;"),
                        payload.replace("<", "&#60;").replace(">", "&#62;"),
                        payload.replace("<", "&#x3C;").replace(">", "&#x3E;"),
                    ]
                    for ev in encoded_versions:
                        if ev in resp_body:
                            html_encoded = True
                            break

                    context = "unknown"
                    if f">{payload}<" in resp_body or f"`{payload}`" in resp_body:
                        context = "html_unquoted"
                    elif f'"{payload}"' in resp_body:
                        context = "attribute_double_quoted"
                    elif f"'{payload}'" in resp_body:
                        context = "attribute_single_quoted"

                    severity = "LOW" if html_encoded else "MEDIUM"
                    evidence = "Payload 被反射"
                    if html_encoded:
                        evidence += "（已 HTML 实体编码，需绕过）"
                    else:
                        evidence += f"（上下文: {context}，未编码）"

                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "severity": severity,
                        "evidence": evidence,
                        "context": context,
                        "html_encoded": html_encoded,
                        "status_code": resp.status_code,
                        "verified": False,
                    })

            except Exception:
                pass

    # ── 二次确认：对未编码反射用不同 payload 向量验证 ──
    raw = [f for f in findings if not f["html_encoded"]]
    verified_count = 0
    for f in raw[:5]:  # 只验证前 5 个
        alt_payloads = ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<body onload=alert(1)>"]
        for alt in alt_payloads:
            if alt == f["payload"]:
                continue
            try:
                if method.upper() == "POST":
                    vresp = await client.post(url, data=body or {f["param"]: alt})
                else:
                    vurl = build_url_with_param(url, f["param"], alt)
                    vresp = await client.get(vurl)
                rb.inc_requests()
                if alt in vresp.text:
                    encoded = any(ev in vresp.text for ev in [
                        alt.replace("<", "&lt;").replace(">", "&gt;"),
                    ])
                    if not encoded:
                        f["verified"] = True
                        f["verified_by"] = f"二次确认: 不同向量 '{alt[:40]}' 同样未编码反射"
                        f["severity"] = "HIGH"
                        verified_count += 1
                        break
            except Exception:
                pass

    # 去重
    seen = set()
    unique = []
    for f in findings:
        key = (f["param"], f["payload"][:15])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    for f in unique:
        rb.add_finding(f)

    if verified_count > 0:
        rb.add_suggestion("确认存在 XSS 反射漏洞，建议在浏览器中手动验证执行")
    elif raw:
        rb.add_suggestion("存在未编码的 Payload 反射但二次确认未通过，建议手动测试")

    return rb.finalize()
