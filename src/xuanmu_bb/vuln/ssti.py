"""SSTI 模板注入检测 — 结构化输出 + 二次确认"""

import re
from typing import Optional

from ..client import HttpClient
from ..data import SSTI_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


async def bb_ssti(
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
    """SSTI 检测 — 多模板引擎盲检测。

    Args:
        url: 目标 URL（含参数）
        custom_payloads: 自定义 SSTI payload（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_ssti", url)

    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    payloads = merge_payloads(SSTI_PAYLOADS, custom_payloads, "custom")
    rb.data["metadata"]["payload_count"] = len(payloads)

    test_params = extract_params_from_url(url, params)
    if not test_params:
        rb.add_suggestion("未找到参数 — 请提供带参数的 URL 或通过 params= 指定")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    try:
        base_resp = await client.get(url)
        rb.inc_requests()
    except Exception:
        pass

    findings = []

    for param in test_params:
        for entry in payloads:
            payload = entry["payload"]
            engine = entry.get("engine", "custom")

            try:
                new_url = build_url_with_param(url, param, payload)
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    resp = await client.get(new_url)
                rb.inc_requests()
                resp_body = resp.text

                # 7*7=49 数学计算执行
                if re.search(r'\b49\b', resp_body) and payload not in resp_body:
                    finding = {
                        "param": param,
                        "payload": payload,
                        "type": "ssti",
                        "engine": engine,
                        "severity": "HIGH",
                        "evidence": "数学计算执行: 7*7 -> 49（确认模板引擎执行）",
                        "status_code": resp.status_code,
                        "verified": False,
                    }
                    # 二次确认: 试 8*8=64
                    try:
                        verify_payload = payload.replace("7*7", "8*8").replace("7*'7'", "8*'8'")
                        if verify_payload != payload:
                            vurl = build_url_with_param(url, param, verify_payload)
                            if method.upper() == "POST":
                                vresp = await client.post(url, data=body or {param: verify_payload})
                            else:
                                vresp = await client.get(vurl)
                            rb.inc_requests()
                            if re.search(r'\b64\b', vresp.text):
                                finding["verified"] = True
                                finding["verified_by"] = "二次确认: 8*8 -> 64"
                                finding["severity"] = "CRITICAL"
                    except Exception:
                        pass
                    findings.append(finding)

                # Config 泄露
                elif "config" in resp_body.lower() and "SECRET_KEY" in resp_body:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": "ssti",
                        "engine": "Jinja2",
                        "severity": "CRITICAL",
                        "evidence": "Config 对象泄露，包含 SECRET_KEY",
                        "status_code": resp.status_code,
                        "verified": True,
                        "verified_by": "响应中包含敏感配置信息",
                    })

            except Exception:
                pass

    for f in findings:
        rb.add_finding(f)

    if any(f.get("verified") for f in findings):
        rb.add_suggestion("确认存在 SSTI 模板注入，根据引擎类型选择 RCE payload")
        engine = findings[0].get("engine", "custom")
        rb.add_suggestion(f"引擎: {engine}，可尝试对应的 RCE payload")

    return rb.finalize()
