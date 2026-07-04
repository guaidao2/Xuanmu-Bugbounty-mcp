"""手工 HTTP 发包工具 — 支持原始请求和拆解参数模式"""

import json
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_send(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    body: Optional[str] = None,
    content_type: Optional[str] = None,
    follow_redirects: bool = True,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """
    手工 HTTP 发包 — 自定义方法/头/Body 发送请求

    Args:
        url: 目标 URL
        method: 请求方法（GET/POST/PUT/DELETE/OPTIONS/PATCH/HEAD）
        headers: 自定义请求头，JSON 格式，如 {"X-Custom": "value"}
        body: 请求体内容
        content_type: Content-Type（快捷设置，会覆盖 headers 中的同名头）
        follow_redirects: 是否跟随重定向（默认 True）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 30）

    Returns:
        完整的请求和响应信息
    """
    url = normalize_url(url)
    method = method.upper()

    # 解析自定义头
    custom_headers = {}
    if headers:
        try:
            custom_headers = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            # 尝试 key:value 分行格式
            for line in headers.split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    custom_headers[k.strip()] = v.strip()

    if content_type and "Content-Type" not in custom_headers:
        custom_headers["Content-Type"] = content_type

    result = []
    result.append("=" * 60)
    result.append("📤 请求")
    result.append("=" * 60)
    result.append(f"{method} {url}")
    if custom_headers:
        for k, v in custom_headers.items():
            result.append(f"{k}: {v}")
    if body:
        result.append("")
        result.append(body[:2000])
    if cookie:
        result.append(f"Cookie: {cookie[:200]}")

    result.append("")
    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.request(
            method=method,
            url=url,
            data=body,
            headers=custom_headers,
            follow_redirects=follow_redirects,
        )

        result.append("=" * 60)
        result.append("📥 响应")
        result.append("=" * 60)
        result.append(f"HTTP {resp.status_code} {resp.reason_phrase}")

        # 响应头
        result.append("")
        result.append("[响应头]")
        for k, v in resp.headers.items():
            result.append(f"  {k}: {v}")

        # 响应体
        result.append("")
        result.append(f"[响应体] ({len(resp.content):,} bytes)")

        # 判断内容类型决定显示方式
        ct = resp.headers.get("Content-Type", "")
        body_text = resp.text

        if "json" in ct:
            try:
                parsed = json.loads(body_text)
                result.append(json.dumps(parsed, ensure_ascii=False, indent=2)[:3000])
            except (json.JSONDecodeError, ValueError):
                result.append(body_text[:2000])
        elif "xml" in ct or "html" in ct:
            result.append(body_text[:2000])
        else:
            result.append(body_text[:2000])

        # 重定向链
        if hasattr(resp, 'history') and resp.history:
            result.append("")
            result.append("[重定向历史]")
            for h in resp.history:
                result.append(f"  {h.status_code} → {h.headers.get('Location', 'N/A')}")

        # 耗时
        elapsed = getattr(resp, 'elapsed', None)
        if elapsed:
            result.append("")
            result.append(f"⏱ 耗时: {elapsed.total_seconds():.2f}s")

    except Exception as e:
        result.append("")
        result.append(f"[!] 请求失败: {e}")

    result.append("")
    result.append("=" * 60)
    return "\n".join(result)
