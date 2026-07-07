"""存活探测工具"""

import asyncio
import socket
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_ping(
    target: str,
    timeout: int = 5,
    proxy: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> str:
    """
    存活探测 — 检测目标是否存活（TCP + HTTP 双重检测）

    Args:
        target: 目标 IP、域名或 URL
        timeout: 超时秒数（默认 5）
        proxy: 代理地址（可选）

    Returns:
        存活状态、响应时间、HTTP 状态码和标题
    """
    results = []

    # 判断是 URL 还是 host
    if target.startswith(("http://", "https://")):
        url = target
        host = target.split("://")[1].split("/")[0].split(":")[0]
    else:
        host = target.strip()
        url = normalize_url(target)

    # ---- TCP Ping ----
    port = 443 if "https://" in url else 80
    try:
        t1 = asyncio.get_event_loop().time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        t2 = asyncio.get_event_loop().time()
        writer.close()
        await writer.wait_closed()
        results.append(f"[+] TCP Ping: {host}:{port} 可达 ({int((t2-t1)*1000)}ms)")
    except (OSError, asyncio.TimeoutError):
        results.append(f"[-] TCP Ping: {host}:{port} 不可达或超时")

    # ---- HTTP Ping ----
    try:
        client = HttpClient(timeout=timeout, proxy=proxy, auth_token=auth_token)
        t1 = asyncio.get_event_loop().time()
        resp = await client.get(url)
        t2 = asyncio.get_event_loop().time()
        resp_time = int((t2 - t1) * 1000)

        # 提取标题
        import re
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:100]

        results.append(f"[+] HTTP Ping: {resp.status_code} ({resp_time}ms) {title}")
        results.append(f"    服务器: {resp.headers.get('Server', 'N/A')}")
        results.append(f"    Content-Type: {resp.headers.get('Content-Type', 'N/A')}")
    except Exception as e:
        results.append(f"[-] HTTP Ping: 失败 — {e}")

    return "\n".join(results)
