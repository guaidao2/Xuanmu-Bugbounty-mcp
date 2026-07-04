"""XSS 检测工具"""

import re
from typing import Optional

import time
from ..client import HttpClient
from ..data.waf import waf_precheck
from ..data import XSS_PAYLOADS
from ..utils import normalize_url
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


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
) -> str:
    """
    XSS 检测 — 反射型 XSS 检测

    Args:
        url: 目标 URL（含参数）
        params: 参数字段名（逗号分隔），默认自动提取
        method: 请求方法（GET/POST）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        反射 XSS 检测结果
    """
    url = normalize_url(url)
    results = []
    _t_start = time.monotonic()
    results.append(f"[*] XSS 检测目标: {url}")
    results.append(f"[*] Payload 数: {len(XSS_PAYLOADS)}")
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


    # 提取参数
    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())

    if not test_params:
        results.append("[!] 未找到参数，请提供带参数的 URL 或通过 params 指定")
        return "\n".join(results)

    findings = []

    for param in test_params:
        for payload_entry in XSS_PAYLOADS:
            payload = payload_entry["payload"]
            ptype = payload_entry["type"]

            try:
                # 构建带 payload 的请求
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [payload]
                    new_qs = urlencode(qs, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_qs))
                    resp = await client.get(new_url)

                body = resp.text

                # 检查 Payload 是否被反射
                if payload in body:
                    # 检查是否被 HTML 实体编码
                    html_encoded = False
                    encoded_versions = [
                        payload.replace("<", "&lt;").replace(">", "&gt;"),
                        payload.replace("<", "&#60;").replace(">", "&#62;"),
                        payload.replace("<", "&#x3C;").replace(">", "&#x3E;"),
                    ]
                    for ev in encoded_versions:
                        if ev in body:
                            html_encoded = True
                            break

                    # 检查上下文
                    context = "unknown"
                    if f">{payload}<" in body or f"`{payload}`" in body:
                        context = "html (unquoted)"
                    elif f'"{payload}"' in body:
                        context = "attribute (double-quoted)"
                    elif f"'{payload}'" in body:
                        context = "attribute (single-quoted)"

                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": ptype,
                        "context": context,
                        "html_encoded": html_encoded,
                        "status": resp.status_code,
                    })

            except Exception as e:
                pass

    if not findings:
        results.append("[-] 未检测到 XSS 反射")
    else:
        # 去重
        seen = set()
        unique = []
        for f in findings:
            key = (f["param"], f["payload"][:15])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        results.append(f"[!] 发现 {len(unique)} 个 Payload 被反射:")
        results.append("")

        # 先显示未编码的（危险系数高）
        raw_reflections = [f for f in unique if not f["html_encoded"]]
        encoded_reflections = [f for f in unique if f["html_encoded"]]

        if raw_reflections:
            results.append("[HIGH] 原始反射（未过滤）:")
            for f in raw_reflections[:10]:
                ctx = f" [上下文: {f['context']}]" if f['context'] != 'unknown' else ""
                results.append(f"  参数: {f['param']}")
                results.append(f"  Payload: {f['payload']}{ctx}")
                results.append(f"  状态码: {f['status']}")
                results.append("")

        if encoded_reflections:
            results.append("[LOW] HTML 实体编码反射（已过滤，可尝试绕过）:")
            for f in encoded_reflections[:10]:
                results.append(f"  参数: {f['param']} | Payload: {f['payload'][:50]}")
            results.append("")

    return "\n".join(results)
