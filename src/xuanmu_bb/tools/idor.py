"""IDOR 越权检测工具 — 双 Token 对比 + 序号枚举"""

import json
from typing import Optional
from urllib.parse import urljoin

from ..client import HttpClient
from ..utils import normalize_url, parse_url


async def bb_idor(
    url: str,
    token_owner: str = "",
    token_attacker: str = "",
    method: str = "GET",
    param: str = "",
    range_start: int = 1,
    range_end: int = 10,
    proxy: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    IDOR 越权检测 — 双 Token 对比 + 序号枚举

    检测方式:
    1. Token 对比: 用 owner/attacker 两个 Token 请求同一资源，对比响应
    2. 序号枚举: 遍历 /resource/1, /resource/2... 检测越权

    Args:
        url: 目标 URL，如 https://api.example.com/users/1234
        token_owner: 资源拥有者的 Bearer Token
        token_attacker: 攻击者/低权限用户的 Bearer Token
        method: 请求方法（GET/POST/PUT/DELETE）
        param: URL 路径中的参数名，如 "user_id" 会尝试替换路径数字
        range_start: 序号枚举起始值（默认 1）
        range_end: 序号枚举结束值（默认 10）
        proxy: 代理地址（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        IDOR 检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] IDOR 越权检测目标: {url}")
    results.append("")

    client_owner = HttpClient(timeout=timeout, proxy=proxy, auth_token=token_owner)
    client_attacker = HttpClient(timeout=timeout, proxy=proxy, auth_token=token_attacker)

    findings = []

    # 1. Token 对比测试
    if token_owner and token_attacker:
        results.append("[*] Token 对比测试:")
        results.append("")
        try:
            resp_owner = await client_owner.request(method, url)
            resp_attacker = await client_attacker.request(method, url)

            status_o, body_o = resp_owner.status_code, resp_owner.text
            status_a, body_a = resp_attacker.status_code, resp_attacker.text

            results.append(f"  [Owner]   HTTP {status_o} ({len(body_o)} bytes)")
            results.append(f"  [Attacker] HTTP {status_a} ({len(body_a)} bytes)")

            # 两者都 200 且内容相似 → 越权!
            if status_o == 200 and status_a == 200:
                # 计算相似度
                body_o_s = body_o.strip()[:500]
                body_a_s = body_a.strip()[:500]
                similarity = len(set(body_o_s.split()) & set(body_a_s.split())) / max(len(set(body_o_s.split()) | set(body_a_s.split())) or 1, 1)
                if similarity > 0.5:
                    findings.append({
                        "type": "水平越权 (IDOR)",
                        "detail": f"Owner 和 Attacker 都返回 HTTP 200，内容相似度 {similarity:.0%}",
                        "severity": "HIGH",
                        "poc": f"curl -H 'Authorization: Bearer {token_attacker[:20]}...' '{url}'",
                    })
                else:
                    results.append(f"  [*] Attacker 响应内容与 Owner 不同（相似度 {similarity:.0%}），可能已鉴权")

            elif status_o == 200 and status_a in (401, 403):
                results.append(f"  [✓] 鉴权正常: Attacker 被拒绝访问 (HTTP {status_a})")

            elif status_o != status_a:
                results.append(f"  [*] 状态码不一致: Owner={status_o}, Attacker={status_a}")

        except Exception as e:
            results.append(f"  [!] 对比请求异常: {e}")
        results.append("")

    # 2. 序号枚举测试
    if param:
        results.append(f"[*] 序号枚举测试 (参数: {param}, 范围: {range_start}-{range_end}):")
        results.append("")
        import re

        for i in range(range_start, range_end + 1):
            # 替换 URL 中的数字参数
            test_url = re.sub(rf'({param}/?)(\d+)', rf'\g<1>{i}', url)
            if test_url == url:
                # 如果没替换成功，尝试追加
                sep = "&" if "?" in url else "/"
                test_url = f"{url}{sep}{param}={i}"

            try:
                resp = await client_attacker.request(method, test_url)
                if resp.status_code == 200:
                    body_preview = resp.text[:100].replace("\n", " ").strip()
                    findings.append({
                        "type": "序号枚举越权",
                        "detail": f"Attacker 可访问 {test_url} (HTTP 200)",
                        "severity": "MEDIUM",
                        "poc": f"curl -H 'Authorization: Bearer {token_attacker[:20]}...' '{test_url}'",
                    })
            except Exception:
                pass

    # 3. 输出
    if not findings:
        results.append("[-] 未检测到 IDOR 越权漏洞")
    else:
        results.append(f"[!] 发现 {len(findings)} 个越权风险:")
        results.append("")
        for f in findings:
            sev = {"HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(f["severity"], "?")
            results.append(f"  {sev} [{f['severity']}] {f['type']}")
            results.append(f"      {f['detail']}")
            if f.get("poc"):
                results.append(f"      PoC: {f['poc']}")
            results.append("")

    # 建议
    results.append("[*] 手动验证建议:")
    results.append("  用两个浏览器的无痕窗口分别登录不同账号")
    results.append("  对比同一接口的返回数据差异")
    results.append("  重点关注: /api/users/, /api/orders/, /api/profile/")

    return "\n".join(results)
