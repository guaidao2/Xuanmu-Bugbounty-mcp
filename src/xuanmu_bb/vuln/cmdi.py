"""命令注入检测 — 结构化输出 + 二次确认"""

import asyncio
from typing import Optional

from ..client import HttpClient
from ..data import CMDI_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


async def bb_cmdi(
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
    """命令注入检测 — 时间盲注 + 输出回显。

    Args:
        url: 目标 URL（含参数）
        custom_payloads: 自定义命令注入 payload（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_cmdi", url)

    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout + 5, proxy=proxy, cookie=cookie, auth_token=auth_token)
    payloads = merge_payloads(CMDI_PAYLOADS, custom_payloads, "custom")
    rb.data["metadata"]["payload_count"] = len(payloads)

    test_params = extract_params_from_url(url, params)
    if not test_params:
        rb.add_suggestion("未找到参数")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    try:
        t1 = asyncio.get_event_loop().time()
        _ = await client.get(url)
        t2 = asyncio.get_event_loop().time()
        base_time = t2 - t1
        rb.inc_requests()
    except Exception:
        base_time = 0.5

    findings = []

    for param in test_params:
        for entry in payloads:
            payload = entry["payload"]
            ptype = entry["type"]

            try:
                new_url = build_url_with_param(url, param, payload)
                t1 = asyncio.get_event_loop().time()
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    resp = await client.get(new_url)
                t2 = asyncio.get_event_loop().time()
                rb.inc_requests()
                resp_time = t2 - t1
                resp_body = resp.text

                evidence = ""
                severity = "INFO"

                if ptype == "time_based" and resp_time > base_time + 2:
                    evidence = f"时间盲注: 响应延迟 {resp_time:.1f}s (基线 {base_time:.1f}s)"
                    severity = "HIGH"
                    # 二次确认：用不同延迟值
                    verified = False
                    verify_payload = payload.replace("ping -c 3", "ping -c 5")
                    if verify_payload != payload:
                        try:
                            vurl = build_url_with_param(url, param, verify_payload)
                            t1 = asyncio.get_event_loop().time()
                            if method.upper() == "POST":
                                _ = await client.post(url, data=body or {param: verify_payload})
                            else:
                                _ = await client.get(vurl)
                            t2 = asyncio.get_event_loop().time()
                            rb.inc_requests()
                            if t2 - t1 > base_time + 4:
                                verified = True
                                evidence += f"; 二次确认: ping -c 5 延迟 {t2-t1:.1f}s"
                                severity = "CRITICAL"
                        except Exception:
                            pass
                    findings.append({
                        "param": param, "payload": payload, "type": ptype,
                        "severity": severity, "evidence": evidence,
                        "response_time": f"{resp_time:.2f}s", "verified": verified,
                    })

                elif ptype == "output":
                    is_reflection = payload.strip(";|&`$() ") in resp_body
                    if "xuanmu_test_" in resp_body or "uid=" in resp_body or "root:" in resp_body:
                        if not is_reflection:
                            evidence = "命令输出回显 (HIGH — 确认命令执行)"
                            findings.append({
                                "param": param, "payload": payload, "type": ptype,
                                "severity": "CRITICAL", "evidence": evidence,
                                "response_time": f"{resp_time:.2f}s", "verified": True,
                                "verified_by": "服务器返回了命令执行结果（非简单反射）",
                            })

                if evidence and not any(f["payload"] == payload for f in findings):
                    findings.append({
                        "param": param, "payload": payload, "type": ptype,
                        "severity": severity, "evidence": evidence,
                        "response_time": f"{resp_time:.2f}s", "verified": False,
                    })

            except Exception:
                pass

    for f in findings:
        rb.add_finding(f)

    if any(f.get("verified") for f in findings):
        rb.add_suggestion("确认存在命令注入，可尝试反弹 shell 或读取敏感文件")

    return rb.finalize()
