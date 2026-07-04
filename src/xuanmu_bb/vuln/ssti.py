"""SSTI 模板注入检测工具"""

import re
from typing import Optional

from ..client import HttpClient
from ..data.waf import waf_precheck
from ..data import SSTI_PAYLOADS
from ..utils import normalize_url
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


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
) -> str:
    """
    SSTI 检测 — 多模板引擎盲检测

    Args:
        url: 目标 URL（含参数）
        params: 参数字段名（逗号分隔）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        检测结果及模板引擎识别
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] SSTI 检测目标: {url}")
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


    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())

    if not test_params:
        results.append("[!] 未找到参数，请提供带参数的 URL")
        return "\n".join(results)

    # 先发一个正常请求拿基线
    try:
        base_resp = await client.get(url)
        base_body = base_resp.text
    except Exception:
        base_body = ""

    findings = []

    for param in test_params:
        for entry in SSTI_PAYLOADS:
            payload = entry["payload"]
            engine = entry["engine"]

            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                new_qs = urlencode(qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_qs))
                if method.upper() == "POST":
                    resp = await client.post(url, data=body or {param: payload})
                else:
                    resp = await client.get(new_url)
                body = resp.text

                # 检测 7*7=49 计算
                if "49" in body and "7*7" not in body:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "engine": engine,
                        "indicator": "数学计算执行: 7*7 → 49",
                    })

                # 检测 config 泄露（Jinja2）
                elif "config" in body.lower() and "SECRET_KEY" in body:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "engine": "Jinja2",
                        "indicator": "Config 对象泄露",
                    })

            except Exception:
                pass

    if not findings:
        results.append("[-] 未检测到 SSTI 注入")
    else:
        results.append(f"[!] 发现 {len(findings)} 个 SSTI 注入点:")
        results.append("")
        for f in findings:
            results.append(f"  参数: {f['param']}")
            results.append(f"  引擎: {f['engine']}")
            results.append(f"  Payload: {f['payload']}")
            results.append(f"  指标: {f['indicator']}")
            results.append("")

    return "\n".join(results)
