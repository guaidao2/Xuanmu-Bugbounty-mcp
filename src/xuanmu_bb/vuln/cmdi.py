"""命令注入检测工具"""

import asyncio
from typing import Optional

from ..client import HttpClient
from ..data import CMDI_PAYLOADS
from ..utils import normalize_url, extract_params_from_url, build_url_with_param, run_waf_precheck


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
) -> str:
    """
    命令注入检测 — 时间盲注 + 输出回显

    Args:
        url: 目标 URL（含参数）
        params: 参数字段名（逗号分隔）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        命令注入检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 命令注入检测目标: {url}")
    results.append(f"[*] Payload 数: {len(CMDI_PAYLOADS)}")
    results.append("")

    client = HttpClient(timeout=timeout + 5, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # WAF 预检（使用公共函数）
    waf_lines = await run_waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay,
                                       proxy=proxy, cookie=cookie, auth_token=auth_token)
    results.extend(waf_lines)

    test_params = extract_params_from_url(url, params)

    if not test_params:
        results.append("[!] 未找到参数")
        return "\n".join(results)

    # 获取基线时间
    try:
        t1 = asyncio.get_event_loop().time()
        _ = await client.get(url)
        t2 = asyncio.get_event_loop().time()
        base_time = t2 - t1
    except Exception:
        base_time = 0.5

    findings = []

    for param in test_params:
        for entry in CMDI_PAYLOADS:
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
                resp_time = t2 - t1
                resp_body = resp.text

                indicators = []

                # 时间盲注 — ping 类 Payload 延迟 > 2s
                if ptype == "time_based" and resp_time > base_time + 2:
                    indicators.append(f"响应延迟 ({base_time:.1f}s -> {resp_time:.1f}s)")

                # 输出回显
                if ptype == "output":
                    is_reflection = payload.strip(";|&`$() ") in resp_body
                    if "xuanmu_test_" in resp_body or "uid=" in resp_body or "root:" in resp_body:
                        if is_reflection:
                            indicators.append("参数反射回显 (LOW — 仅为参数回显，非命令执行)")
                        else:
                            indicators.append("命令输出回显 (HIGH — 确认命令执行)")

                if indicators:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "indicators": indicators,
                        "response_time": f"{resp_time:.2f}s",
                    })

            except Exception:
                pass

    if not findings:
        results.append("[-] 未检测到命令注入")
    else:
        results.append(f"[!] 发现 {len(findings)} 个可疑命令注入点:")
        results.append("")
        for f in findings:
            results.append(f"  参数: {f['param']}")
            results.append(f"  类型: {f['type']}")
            results.append(f"  Payload: {f['payload']}")
            results.append(f"  响应时间: {f['response_time']}")
            results.append(f"  指标: {'; '.join(f['indicators'])}")
            results.append("")

    return "\n".join(results)
