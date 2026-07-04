"""目录爆破工具"""

import asyncio
from typing import Optional

import time
from ..client import HttpClient
from ..data import DIR_DICT
from ..data.waf import waf_precheck
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
    waf_mode: str = "safe",
    max_retries_on_block: int = 3,
    request_delay: float = 0.5,
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
    # WAF 预检
    if waf_mode != "off":
        _w = await waf_precheck(base_url, waf_mode=waf_mode, request_delay=request_delay, proxy=proxy, cookie=cookie, auth_token=auth_token)
        if _w["waf_detected"]:
            _wn = _w.get("waf_name","")
    _wd = _w.get("delay",0)
    results.append(f"[!] WAF 检测: " + _wn + " 自动降速至 " + str(_wd) + "s")
    for s in _w["suggestions"]:
        results.append(f"    绕过: " + s)

    sem = asyncio.Semaphore(concurrent)

    tasks = [_check_path(client, base_url, p, sem, timeout) for p in paths]
    done = await asyncio.gather(*tasks)

    found = [r for r in done if r["status"] in filter_codes]

    # 302 去重：相同跳转模式聚合
    redirect_groups = {}
    non_redirect = []
    for r in found:
        if r["status"] in (301, 302, 303, 307, 308) and r.get("location"):
            base_loc = r["location"].split("?")[0].rstrip("/")
            # 提取跳转中的可变部分（/xxx/same.psp → /*/same.psp）
            import re as re2
            pattern = re2.sub(r'/[^/]+(?=/)', '/*', base_loc)
            key = f"{r['status']} → {pattern}"
            if key not in redirect_groups:
                redirect_groups[key] = {"count": 0, "samples": [], "status": r['status']}
            redirect_groups[key]["count"] += 1
            if len(redirect_groups[key]["samples"]) < 3:
                redirect_groups[key]["samples"].append(r['path'])
        else:
            non_redirect.append(r)

    if not found:
        results.append("[!] 未发现感兴趣的路径")
    else:
        total_unique = len(non_redirect) + len(redirect_groups)
        results.append(f"[✓] 发现 {len(found)} 个路径（去重后 {total_unique} 组）:")
        results.append("")
        # 先显示非重定向
        if non_redirect:
            results.append(f"    {'状态码':<8} {'大小':<10} {'路径':<50}")
            results.append(f"    {'-'*70}")
            for r in sorted(non_redirect, key=lambda x: x["status"]):
                size_str = f"{r['size']:,}" if r["size"] else "-"
                loc_str = f" → {r['location']}" if r.get("location") else ""
                results.append(f"    {r['status']:<8} {size_str:<10} /{r['path'].lstrip('/')}{loc_str}")
        # 再显示聚合的重定向组
        if redirect_groups:
            results.append("")
            results.append(f"    [重定向聚合] ({len(redirect_groups)} 组):")
            for key, info in sorted(redirect_groups.items()):
                samples = ", /".join([s.lstrip("/") for s in info["samples"]])
                results.append(f"    {info['status']:<8} 共 {info['count']} 条 → {key.split('→')[1].strip()}")
                results.append(f"           示例: /{samples}")

    return "\n".join(results)
