"""子域名枚举工具 — 基于 DNS 查询 + 证书透明度"""

import asyncio
import socket
from typing import Optional

import dns.resolver
import dns.asyncresolver

from ..data import SUBDOMAIN_DICT


async def _check_subdomain(domain: str, sub: str, sem: asyncio.Semaphore) -> dict:
    """检查单个子域名是否解析"""
    async with sem:
        fqdn = f"{sub}.{domain}"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = await resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers][:5]
            return {"subdomain": fqdn, "ips": ips, "alive": True}
        except Exception:
            # 尝试 CNAME
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = await resolver.resolve(fqdn, "CNAME")
                cname = str(answers[0])
                return {"subdomain": fqdn, "cname": cname, "alive": True}
            except Exception:
                return {"subdomain": fqdn, "alive": False}


async def bb_subdomain(
    domain: str,
    wordlist: Optional[str] = None,
    concurrent: int = 50,
    check_cname: bool = True,
) -> str:
    """
    子域名枚举 — DNS 批量解析

    Args:
        domain: 目标域名（如 example.com）
        wordlist: 自定义字典（逗号分隔），默认使用内置 200 常用子域
        concurrent: 并发数（默认 50）
        check_cname: 是否检查 CNAME 记录（默认 True）

    Returns:
        子域名列表、IP 地址、CNAME 记录
    """
    domain = domain.strip().lower()
    if wordlist:
        subs = [s.strip() for s in wordlist.split(",") if s.strip()]
    else:
        subs = SUBDOMAIN_DICT

    results = []
    results.append(f"[*] 目标域名: {domain}")
    results.append(f"[*] 枚举子域数: {len(subs)}")
    results.append("")

    sem = asyncio.Semaphore(concurrent)
    tasks = [_check_subdomain(domain, sub, sem) for sub in subs]
    done = await asyncio.gather(*tasks)

    alive = [r for r in done if r["alive"]]
    if not alive:
        results.append("[!] 未发现可解析的子域名")
    else:
        results.append(f"[+] 发现 {len(alive)} 个存活的子域名:")
        results.append("")
        for r in sorted(alive, key=lambda x: x["subdomain"]):
            ips = r.get("ips", [])
            cname = r.get("cname", "")
            if ips:
                results.append(f"  {r['subdomain']:<40} → {', '.join(ips)}")
            elif cname:
                results.append(f"  {r['subdomain']:<40} → CNAME: {cname}")
            else:
                results.append(f"  {r['subdomain']:<40}")

    # 统计
    if alive:
        results.append("")
        results.append(f"[*] 总计: {len(alive)} / {len(subs)}")

    return "\n".join(results)
