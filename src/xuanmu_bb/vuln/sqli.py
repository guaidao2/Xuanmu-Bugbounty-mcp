"""SQL 注入检测工具"""

import asyncio
import re
import time
from typing import Optional

from ..client import HttpClient
from ..data.waf import waf_precheck
from ..data import SQLI_PAYLOADS
from ..utils import normalize_url, extract_params_from_url, build_url_with_param, run_waf_precheck


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
) -> str:
    """
    SQL 注入检测 — 报错/布尔/时间盲注

    Args:
        url: 目标 URL（含参数或 POST API）
        params: 参数字段名（逗号分隔），默认自动提取
        method: 请求方法（GET/POST）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）
        delay: 请求间隔秒数（默认 0.5）

    Returns:
        可疑注入点及类型
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] SQLi 检测目标: {url}")
    results.append(f"[*] Payload 数: {len(SQLI_PAYLOADS)}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, delay=delay, auth_token=auth_token)

    # WAF 预检（使用公共函数）
    waf_lines = await run_waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay,
                                       proxy=proxy, cookie=cookie, auth_token=auth_token)
    results.extend(waf_lines)

    # 自动检测表单 method
    auto_method = method.upper()
    if auto_method == "GET" and not params:
        try:
            _page_resp = await client.get(url)
            _form_m = re.search(r'<form[^>]*method=["\'](post)["\']', _page_resp.text, re.IGNORECASE)
            if _form_m:
                auto_method = "POST"
                results.append("[*] 页面检测到 POST 表单，自动切换为 POST 方法")
        except Exception:
            pass
    method = auto_method
    results.append(f"[*] 方法: {method}")

    try:
        # 获取原始响应作为基线
        if method.upper() == "POST":
            base_resp = await client.post(url)
        else:
            base_resp = await client.get(url)

        base_length = len(base_resp.content)
        base_time = base_resp.elapsed.total_seconds() if hasattr(base_resp, 'elapsed') else 0

        results.append(f"[*] 基线: 状态={base_resp.status_code}, 大小={base_length}")
        auth_status = "required" if base_resp.status_code in (401, 403) else "none"
        results.append(f"[AUTH: {auth_status}] HTTP {base_resp.status_code}")
        results.append("")
    except Exception as e:
        results.append(f"[!] 基线请求失败: {e}")
        return "\n".join(results)

    # 如果指定了参数，逐个测试
    test_params = extract_params_from_url(url, params)
    if not test_params and method.upper() == "GET":
        results.append("[!] 未找到参数，请使用 ?key=value 格式的 URL 或通过 params 指定")
        return "\n".join(results)

    findings = []

    for param in test_params:
        for payload_entry in SQLI_PAYLOADS:
            payload = payload_entry["payload"]
            ptype = payload_entry["type"]
            test_value = f"1{payload}" if payload.startswith(("'", '"')) else payload

            try:
                # 构造带 payload 的请求
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: test_value})
                else:
                    new_url = build_url_with_param(url, param, test_value)
                    resp = await client.get(new_url)

                resp_length = len(resp.content)
                resp_time = resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0
                resp_text = resp.text.lower()

                indicators = []

                # 报错检测
                if ptype == "error_based":
                    error_patterns = [
                        "sql", "mysql", "oracle", "postgresql", "sqlite",
                        "syntax error", "unclosed", "quotation mark",
                        "odbc", "driver", "db2", "microsoft ole db",
                        "warning: mysql", "supplied argument",
                        "you have an error in your sql",
                    ]
                    for pat in error_patterns:
                        if pat in resp_text:
                            indicators.append(f"数据库错误: {pat}")

                # 布尔检测（响应长度变化）
                elif ptype == "boolean":
                    if "1=2" in payload or "1'='2" in payload:
                        if abs(resp_length - base_length) > 50:
                            indicators.append(f"响应大小变化 ({base_length} -> {resp_length})")

                # 时间盲注检测
                elif ptype == "time_based" and "sleep" in payload.lower():
                    if resp_time > base_time + 2:
                        indicators.append(f"响应延迟 ({resp_time:.1f}s)")

                if indicators:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "indicators": indicators,
                        "status": resp.status_code,
                        "length_diff": resp_length - base_length,
                        "time_diff": resp_time - base_time,
                    })

            except Exception as e:
                if "timeout" in str(e).lower():
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "indicators": ["请求超时 — 可能存在时间盲注"],
                        "status": 0,
                        "length_diff": 0,
                        "time_diff": timeout,
                    })

    if not findings:
        results.append("[-] 未检测到 SQL 注入")
    else:
        # 去重，只保留最可疑的
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["param"], f["payload"][:20])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        results.append(f"[!] 发现 {len(unique_findings)} 个可疑注入点:")
        results.append("")
        for f in unique_findings[:20]:  # 最多显示 20 条
            results.append(f"  参数: {f['param']}")
            results.append(f"  类型: {f['type']}")
            results.append(f"  Payload: {f['payload']}")
            results.append(f"  状态码: {f['status']}")
            results.append(f"  指标: {'; '.join(f['indicators'])}")
            results.append("")

    return "\n".join(results)
