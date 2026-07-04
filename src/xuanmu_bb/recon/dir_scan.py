"""目录爆破工具"""

import asyncio
from typing import Optional

from ..client import HttpClient
from ..data import DIR_DICT
from ..utils import normalize_url


async def _check_path(
    client: HttpClient,
    base_url: str,
    path: str,
    sem: asyncio.Semaphore,
    timeout: int,
) -> dict:
    """检查单个路径"""
    async with sem:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            resp = await client.get(url, follow_redirects=False)
            status = resp.status_code
            size = len(resp.content)
            location = resp.headers.get("Location", "")[:100] if status in (301, 302, 307, 308) else ""
            return {
                "path": "/" + path.lstrip("/"),
                "status": status,
                "size": size,
                "location": location,
            }
        except Exception:
            return {"path": path, "status": 0, "size": 0, "location": ""}


async def bb_dir_scan(
    url: str,
    wordlist: Optional[str] = None,
    status_filter: str = "200,301,302,307,308,401,403,405,500",
    concurrent: int = 30,
    timeout: int = 10,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
) -> str:
    """
    目录/文件爆破

    Args:
        url: 目标 URL（如 https://example.com）
        wordlist: 自定义路径字典（逗号分隔），默认使用内置 150+ 路径
        status_filter: 关心的状态码（默认 200,301,302,307,308,401,403,405,500）
        concurrent: 并发数（默认 30）
        timeout: 超时秒数（默认 10）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）

    Returns:
        发现的路径列表及状态码
    """
    base_url = normalize_url(url)
    filter_codes = {int(s.strip()) for s in status_filter.split(",") if s.strip().isdigit()}

    if wordlist:
        paths = [p.strip() for p in wordlist.split(",") if p.strip()]
    else:
        paths = DIR_DICT

    results = []
    _t_start = time.monotonic()
    results.append(f"[*] 目标: {base_url}")
    results.append(f"[*] 字典大小: {len(paths)}")
    results.append(f"[*] 关注状态码: {sorted(filter_codes)}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, delay=0.05, auth_token=auth_token)
    sem = asyncio.Semaphore(concurrent)

    tasks = [_check_path(client, base_url, p, sem, timeout) for p in paths]
    done = await asyncio.gather(*tasks)

    found = [r for r in done if r["status"] in filter_codes]

    if not found:
        results.append("[!] 未发现感兴趣的路径")
    else:
        results.append(f"[✓] 发现 {len(found)} 个路径:")
        results.append("")
        results.append(f"    {'状态码':<8} {'大小':<10} {'路径':<50}")
        results.append(f"    {'-'*70}")
        for r in sorted(found, key=lambda x: x["status"]):
            size_str = f"{r['size']:,}" if r["size"] else "-"
            loc_str = f" → {r['location']}" if r["location"] else ""
            results.append(f"    {r['status']:<8} {size_str:<10} /{r['path'].lstrip('/')}{loc_str}")

    return "\n".join(results)
