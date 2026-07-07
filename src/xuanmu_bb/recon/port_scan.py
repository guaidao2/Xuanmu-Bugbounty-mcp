"""端口扫描工具 — 基于 asyncio TCP Connect"""

import asyncio
import socket
from typing import Optional

from ..data.dicts import COMMON_PORTS, TOP_PORTS
from ..utils import parse_ports


async def _scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    """扫描单个端口"""
    async with sem:
        try:
            t1 = asyncio.get_event_loop().time()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            t2 = asyncio.get_event_loop().time()
            writer.close()
            await writer.wait_closed()
            service = COMMON_PORTS.get(port, "Unknown")
            return {
                "port": port,
                "state": "open",
                "service": service,
                "time_ms": int((t2 - t1) * 1000),
            }
        except (OSError, asyncio.TimeoutError):
            return {"port": port, "state": "closed", "service": "", "time_ms": 0}


async def bb_port_scan(
    target: str,
    ports: str = "top100",
    timeout: int = 3,
    concurrent: int = 200,
) -> str:
    """
    端口扫描 — TCP Connect 方式，无第三方依赖

    Args:
        target: 目标 IP 或域名
        ports: 端口范围，如 "80,443,8080-8090"，默认 "top100"
        timeout: 单端口超时秒数（默认 3）
        concurrent: 并发数（默认 200）

    Returns:
        开放端口列表及服务识别
    """
    if ports.lower() == "top100":
        port_list = TOP_PORTS
    else:
        port_list = parse_ports(ports)

    host = target.strip()

    # 先解析域名
    try:
        import socket as sock
        ip = sock.gethostbyname(host)
    except Exception:
        ip = host

    sem = asyncio.Semaphore(concurrent)
    tasks = [_scan_port(host, p, timeout, sem) for p in port_list]

    results = []
    total = len(port_list)
    results.append(f"[*] 目标: {host} ({ip})")
    results.append(f"[*] 扫描端口数: {total}")
    results.append("")

    done = await asyncio.gather(*tasks)
    open_ports = [r for r in done if r["state"] == "open"]

    if not open_ports:
        results.append("[!] 未发现开放端口")
    else:
        results.append(f"[+] 发现 {len(open_ports)} 个开放端口:")
        results.append(f"    {'端口':<8} {'服务':<20} {'延迟':<8}")
        results.append(f"    {'-'*40}")
        for r in sorted(open_ports, key=lambda x: x["port"]):
            results.append(f"    {r['port']:<8} {r['service']:<20} {r['time_ms']}ms")

    return "\n".join(results)
