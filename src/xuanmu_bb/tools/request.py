"""手工 HTTP 发包工具 — JSON/form/multipart 全格式兼容"""

import json
import os as _os
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_send(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    body: Optional[str] = None,
    content_type: Optional[str] = None,
    files: Optional[str] = None,
    follow_redirects: bool = True,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """
    手工 HTTP 发包 — 支持 JSON / form / multipart / 文件上传 / XML / 纯文本

    Args:
        url: 目标 URL
        method: 请求方法（GET/POST/PUT/DELETE/OPTIONS/PATCH/HEAD）
        headers: 自定义请求头，JSON 格式 {"X-Custom":"v"} 或 key:value 分行格式
        body: 请求体。自动识别：
              {"key":"value"} -> JSON
              key=value&foo=bar -> form
              <root>data</root> -> XML（需配合 content_type="application/xml"）
        content_type: 手动指定 Content-Type（覆盖自动检测）
        files: 文件上传，格式 "field=/path/to/file" 或逗号分隔多个 "f1=/a.txt,f2=/b.png"
              若路径不存在则作为普通文本字段值
        follow_redirects: 是否跟随重定向（默认 True）
        proxy: 代理地址
        cookie: Cookie
        auth_token: Bearer Token
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
            for line in headers.split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    custom_headers[k.strip()] = v.strip()

    # --- 文件上传处理 ---
    file_dict = None
    has_files = False
    if files:
        file_dict = {}
        for item in files.split(","):
            item = item.strip()
            if "=" in item:
                key, path = item.split("=", 1)
                key, path = key.strip(), path.strip()
                if _os.path.isfile(path):
                    file_dict[key] = open(path, "rb")
                    has_files = True
                else:
                    # 路径不存在，作为普通文本字段
                    file_dict[key] = path
        if has_files:
            # multipart 不需要我们手动设 Content-Type，httpx 会自动加 boundary
            custom_headers.pop("Content-Type", None)

    # --- JSON 自动检测 ---
    is_json = False
    json_body = None

    if body:
        body_stripped = body.strip()
        if body_stripped.startswith("{") or body_stripped.startswith("["):
            try:
                json_body = json.loads(body_stripped)
                is_json = True
            except (json.JSONDecodeError, ValueError):
                is_json = False

    # Content-Type 处理
    if content_type:
        custom_headers["Content-Type"] = content_type
        if "json" in content_type and body and not is_json:
            try:
                json_body = json.loads(body.strip())
                is_json = True
            except (json.JSONDecodeError, ValueError):
                pass
    elif is_json:
        custom_headers["Content-Type"] = "application/json"
    elif body and method in ("POST", "PUT", "PATCH") and not has_files:
        custom_headers["Content-Type"] = "application/x-www-form-urlencoded"

    result = []
    result.append("=" * 60)
    result.append("[Request]")
    result.append("=" * 60)
    result.append(f"{method} {url}")
    if custom_headers:
        for k, v in custom_headers.items():
            result.append(f"{k}: {v}")
    if body:
        result.append("")
        result.append(body[:2000])
    if has_files:
        result.append("")
        result.append(f"[Files] {files}")
    if cookie:
        result.append(f"Cookie: {cookie[:200]}")

    result.append("")
    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        # 根据类型选择发送方式
        if has_files and file_dict:
            resp = await client.request(
                method=method, url=url,
                files=file_dict, data=body,
                headers=custom_headers, follow_redirects=follow_redirects,
            )
        elif is_json and json_body is not None:
            resp = await client.request(
                method=method, url=url, json_data=json_body,
                headers=custom_headers, follow_redirects=follow_redirects,
            )
        else:
            resp = await client.request(
                method=method, url=url, data=body,
                headers=custom_headers, follow_redirects=follow_redirects,
            )

        result.append("=" * 60)
        result.append("[Response]")
        result.append("=" * 60)
        result.append(f"HTTP {resp.status_code} {resp.reason_phrase}")

        result.append("")
        result.append("[Response Headers]")
        for k, v in resp.headers.items():
            result.append(f"  {k}: {v}")

        result.append("")
        result.append(f"[Response Body] ({len(resp.content):,} bytes)")

        ct = resp.headers.get("Content-Type", "")
        body_text = resp.text

        if "json" in ct:
            try:
                parsed = json.loads(body_text)
                result.append(json.dumps(parsed, ensure_ascii=False, indent=2)[:3000])
            except (json.JSONDecodeError, ValueError):
                result.append(body_text[:2000])
        else:
            result.append(body_text[:2000])

        if hasattr(resp, 'history') and resp.history:
            result.append("")
            result.append("[Redirect History]")
            for h in resp.history:
                result.append(f"  {h.status_code} -> {h.headers.get('Location', 'N/A')}")

        elapsed = getattr(resp, 'elapsed', None)
        if elapsed:
            result.append("")
            result.append(f"[Time] {elapsed.total_seconds():.2f}s")

    except Exception as e:
        result.append("")
        result.append(f"[!] Request failed: {e}")
    finally:
        # 关闭打开的文件句柄
        if file_dict:
            for v in file_dict.values():
                if hasattr(v, "close"):
                    v.close()

    result.append("")
    result.append("=" * 60)
    return "\n".join(result)
