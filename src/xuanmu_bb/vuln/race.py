"""条件竞争检测工具"""

import asyncio
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_race(
    url: str,
    method: str = "POST",
    data: Optional[str] = None,
    concurrent: int = 20,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    条件竞争检测 — 并发请求测试

    适用于:
    - 并发领取优惠券/积分
    - 并发下单/扣库存
    - 并发提现
    - 并发投票/点赞
    - 并发修改用户信息

    Args:
        url: 目标 URL（敏感操作的接口）
        method: 请求方法（默认 POST）
        data: POST 数据（可选）
        concurrent: 并发请求数（默认 20）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        条件竞争检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 条件竞争检测目标: {url}")
    results.append(f"[*] 并发数: {concurrent}")
    results.append(f"[*] 方法: {method}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    # 1. 先发一个正常请求做基线
    try:
        if method.upper() == "POST":
            base_resp = await client.post(url, data=data)
        else:
            base_resp = await client.get(url)
        base_status = base_resp.status_code
        base_body_len = len(base_resp.content)
        results.append(f"[*] 基线: {base_status} ({base_body_len} bytes)")
        results.append("")
    except Exception as e:
        base_status = 0
        base_body_len = 0
        results.append(f"[*] 基线请求失败: {e}")
        results.append("")

    # 2. 并发请求
    results.append(f"[*] 正在发送 {concurrent} 个并发请求...")
    results.append("")

    async def _race_request(idx: int) -> dict:
        try:
            if method.upper() == "POST":
                resp = await client.post(url, data=data)
            else:
                resp = await client.get(url)
            return {
                "index": idx,
                "status": resp.status_code,
                "length": len(resp.content),
                "body": resp.text[:200],
            }
        except Exception as e:
            return {"index": idx, "status": 0, "length": 0, "body": str(e)}

    tasks = [_race_request(i) for i in range(concurrent)]
    responses = await asyncio.gather(*tasks)

    # 3. 分析结果
    status_codes = {}
    body_lengths = {}
    unique_bodies = set()

    for r in responses:
        status_codes[r["status"]] = status_codes.get(r["status"], 0) + 1
        body_lengths[r["length"]] = body_lengths.get(r["length"], 0) + 1
        unique_bodies.add(r["body"])

    # 输出统计
    results.append(f"[*] 响应状态码分布:")
    for sc in sorted(status_codes.keys()):
        sc_str = f"  {sc} ({'成功' if sc == 200 else '跳转' if sc in (301,302) else '错误' if sc >= 400 else '其他'}): {status_codes[sc]}次"
        results.append(sc_str)

    results.append("")
    results.append(f"[*] 响应体长度分布:")
    for bl in sorted(body_lengths.keys()):
        results.append(f"  长度 {bl}: {body_lengths[bl]}次")

    # 4. 检测竞争条件
    race_flags = []

    # 检查是否有不同的响应内容（竞赛成功标志）
    if len(unique_bodies) > 1:
        # 正常响应应只有 1 种内容，多余表示不同结果
        race_flags.append(f"存在 {len(unique_bodies)} 种不同响应内容")

    # 检查是否有 200 成功比例异常（某些请求成功而其他失败）
    success_count = status_codes.get(200, 0)
    if success_count > 0 and success_count < concurrent:
        race_flags.append(f"{success_count}/{concurrent} 请求返回 200（部分成功/部分失败）")

    # 检查 500 错误（服务端并发处理出错）
    if status_codes.get(500, 0) > 0:
        race_flags.append(f"出现 {status_codes[500]} 次 500 错误（服务端并发冲突）")

    # 检查多个长度分布
    if len(body_lengths) > 2:
        race_flags.append(f"响应长度分布分散（{len(body_lengths)} 种不同长度）")

    if race_flags:
        results.append("")
        results.append("[!] 条件竞争检测发现:")
        for flag in race_flags:
            results.append(f"  ⚠️  {flag}")
        results.append("")
        results.append("[🔥] 可能存在条件竞争漏洞，建议手动验证:")
        results.append("  └─ 在 SRC 场景中，重点关注: 并发领取/扣款/抽奖/修改资源")
    else:
        results.append("")
        results.append("[✓] 未发现明显的条件竞争异常")
        results.append("  └─ 所有请求行为一致")

    results.append("")
    results.append("[*] Race Condition 手动验证技巧:")
    results.append("  🔸 使用 Burp Suite Turbo Intruder 的 'race-single-packet-attack'")
    results.append("  🔸 使用 Python asyncio + asyncio.gather() 发送真正的同时请求")
    results.append("  🔸 关注: 库存操作 / 余额操作 / 抽奖 / 优惠券领取")

    return "\n".join(results)
