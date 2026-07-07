"""SQL 注入检测工具 — 结构化输出 + 二次确认"""

import asyncio
import re
import time
from typing import Optional

from ..client import HttpClient
from ..data import SQLI_PAYLOADS
from ..utils import (
    normalize_url, extract_params_from_url, build_url_with_param,
    merge_payloads, ResultBuilder, run_waf_precheck_structured,
)


async def bb_sqli(
    url: str,
    params: str = "",
    method: str = "GET",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
    delay: float = 0.5,
    waf_mode: str = "safe",
    max_retries_on_block: int = 3,
    request_delay: float = 0.5,
    body: str = "",
    custom_payloads: str = "",
) -> dict:
    """SQL 注入检测 — 报错/布尔/时间盲注。

    Args:
        url: 目标 URL（含参数或 POST API）
        params: 参数字段名（逗号分隔），默认自动提取
        custom_payloads: 自定义 SQLi payload（逗号分隔）
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_sqli", url)

    # WAF 预检
    waf = await run_waf_precheck_structured(url, waf_mode=waf_mode, request_delay=request_delay,
                                            proxy=proxy, cookie=cookie, auth_token=auth_token)
    rb.set_waf(waf["waf_name"], waf["suggestions"])

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, delay=delay, auth_token=auth_token)

    # 合并自定义 payload
    payloads = merge_payloads(SQLI_PAYLOADS, custom_payloads, "custom")

    # 自动检测表单 method
    auto_method = method.upper()
    if auto_method == "GET" and not params:
        try:
            _page_resp = await client.get(url)
            _form_m = re.search(r'<form[^>]*method=["\'](post)["\']', _page_resp.text, re.IGNORECASE)
            if _form_m:
                auto_method = "POST"
        except Exception:
            pass
    method = auto_method
    rb.data["metadata"]["method"] = method
    rb.data["metadata"]["payload_count"] = len(payloads)

    # 获取基线
    try:
        if method.upper() == "POST":
            base_resp = await client.post(url)
        else:
            base_resp = await client.get(url)
        rb.inc_requests()
        base_length = len(base_resp.content)
        base_time = base_resp.elapsed.total_seconds() if hasattr(base_resp, 'elapsed') else 0
        auth_status = "required" if base_resp.status_code in (401, 403) else "none"
        rb.data["metadata"]["auth_status"] = auth_status
    except Exception as e:
        return rb.finalize("error")

    # 提取参数
    test_params = extract_params_from_url(url, params)
    if not test_params and method.upper() == "GET":
        rb.add_suggestion("未找到参数 — 请使用 ?key=value 格式或 params= 指定参数")
        return rb.finalize("error")
    rb.set_params_tested(test_params)

    findings = []

    for param in test_params:
        for payload_entry in payloads:
            payload = payload_entry["payload"]
            ptype = payload_entry["type"]
            test_value = f"1{payload}" if payload.startswith(("'", '"')) else payload

            try:
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: test_value})
                else:
                    new_url = build_url_with_param(url, param, test_value)
                    resp = await client.get(new_url)
                rb.inc_requests()

                resp_length = len(resp.content)
                resp_time = resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0
                resp_text = resp.text.lower()

                evidence = ""
                severity = "INFO"

                # 报错检测
                if ptype in ("error_based", "custom"):
                    error_patterns = [
                        "sql", "mysql", "oracle", "postgresql", "sqlite",
                        "syntax error", "unclosed", "quotation mark",
                        "odbc", "driver", "db2", "microsoft ole db",
                        "you have an error in your sql",
                    ]
                    for pat in error_patterns:
                        if pat in resp_text:
                            evidence = f"数据库错误信息泄露: {pat}"
                            severity = "HIGH"
                            break

                # 布尔检测
                elif ptype == "boolean":
                    if ("1=2" in payload or "1'='2" in payload) and abs(resp_length - base_length) > 50:
                        evidence = f"布尔盲注: 响应大小变化 ({base_length} -> {resp_length})"
                        severity = "HIGH"

                # 时间盲注
                elif ptype == "time_based" and "sleep" in payload.lower():
                    if resp_time > base_time + 2:
                        evidence = f"时间盲注: 响应延迟 {resp_time:.1f}s (基线 {base_time:.1f}s)"
                        severity = "HIGH"

                if evidence:
                    finding = {
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "severity": severity,
                        "evidence": evidence,
                        "status_code": resp.status_code,
                        "length_diff": resp_length - base_length,
                        "time_diff": round(resp_time - base_time, 2),
                        "verified": False,
                    }
                    findings.append(finding)

            except Exception as e:
                if "timeout" in str(e).lower():
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "severity": "MEDIUM",
                        "evidence": "请求超时 — 可能存在时间盲注",
                        "status_code": 0,
                        "verified": False,
                    })

    # ── 二次确认（Verification）──
    verified_findings = []
    for f in findings:
        if f["type"] == "time_based" and not f.get("verified"):
            # 用不同的 sleep 值重试确认
            verify_payload = f["payload"].replace("SLEEP(3)", "SLEEP(5)").replace("sleep(3)", "sleep(5)")
            if verify_payload != f["payload"]:
                try:
                    test_value = f"1{verify_payload}" if verify_payload.startswith(("'", '"')) else verify_payload
                    new_url = build_url_with_param(url, f["param"], test_value)
                    t1 = asyncio.get_event_loop().time()
                    if method.upper() == "POST":
                        vresp = await client.post(url, data=body or {f["param"]: test_value})
                    else:
                        vresp = await client.get(new_url)
                    t2 = asyncio.get_event_loop().time()
                    rb.inc_requests()
                    vt = t2 - t1
                    if vt > base_time + 4:
                        f["verified"] = True
                        f["verified_by"] = f"二次确认: sleep(5) 延迟 {vt:.1f}s (基线 {base_time:.1f}s)"
                        f["severity"] = "CRITICAL"
                except Exception:
                    pass

        elif f["type"] == "boolean" and not f.get("verified"):
            # 用不同的 true/false 对重试
            try:
                verify_true = f["payload"].replace("1=1", "2=2").replace("1'='1", "2'='2")
                verify_false = f["payload"].replace("1=2", "2=1").replace("1'='2", "2'='1")

                new_url_t = build_url_with_param(url, f["param"], f"1{verify_true}" if verify_true.startswith(("'", '"')) else verify_true)
                new_url_f = build_url_with_param(url, f["param"], f"1{verify_false}" if verify_false.startswith(("'", '"')) else verify_false)

                if method.upper() == "POST":
                    resp_t = await client.post(url, data=body or {f["param"]: verify_true})
                    resp_f = await client.post(url, data=body or {f["param"]: verify_false})
                else:
                    resp_t = await client.get(new_url_t)
                    resp_f = await client.get(new_url_f)
                rb.inc_requests(2)

                if abs(len(resp_t.content) - len(resp_f.content)) > 50:
                    f["verified"] = True
                    f["verified_by"] = f"二次确认: true/false 响应差异 {abs(len(resp_t.content) - len(resp_f.content))} bytes"
                    f["severity"] = "CRITICAL"
            except Exception:
                pass

        verified_findings.append(f)

    for f in verified_findings:
        rb.add_finding(f)

    # 建议
    if any(f.get("verified") for f in verified_findings):
        rb.add_suggestion("确认存在 SQL 注入，建议使用 sqlmap 进一步利用")
        rb.add_suggestion(f"sqlmap -u \"{url}\" --param=\"{verified_findings[0]['param']}\" --batch --dbs")

    return rb.finalize()
