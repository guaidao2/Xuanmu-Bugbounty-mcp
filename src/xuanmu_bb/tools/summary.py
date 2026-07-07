"""扫描报告聚合工具 — 汇总所有发现的资产与漏洞"""

from typing import Optional


async def bb_summary(
    url: str = "",
    findings: Optional[str] = None,
) -> str:
    """
    扫描报告聚合 — 汇总当前目标的资产发现与漏洞

    用法：将之前各工具的扫描输出粘贴到 findings 参数中，
    工具会自动解析并生成结构化报告。

    Args:
        url: 目标 URL（可选）
        findings: 各工具扫描结果的文本（可选），
                  工具自动从中提取关键发现

    Returns:
        聚合后的结构化扫描报告
    """
    result = []
    result.append("=" * 60)
    result.append("[Report] Xuanmu Bug Bounty 扫描报告")
    if url:
        result.append(f"   目标: {url}")
    result.append("=" * 60)
    result.append("")

    # 如果没有 findings，提供使用指引
    if not findings:
        result.append("[*] 扫描报告生成器")
        result.append("")
        result.append("使用方法:")
        result.append("  1. 依次运行各扫描工具收集结果")
        result.append("  2. 将各工具的文本输出传入 findings 参数")
        result.append("  3. 工具自动提取关键发现并生成结构化报告")
        result.append("")
        result.append("示例流程:")
        result.append(f"  bb_fingerprint  url=\"{url or 'https://target.com'}\"")
        result.append(f"  bb_dir_scan     url=\"{url or 'https://target.com'}\"")
        result.append(f"  bb_param_discover url=\"{url or 'https://target.com'}\"")
        result.append(f"  bb_sqli         url=\"{url or 'https://target.com/page?id=1'}\"")
        result.append(f"  bb_xss          url=\"{url or 'https://target.com/search?q=test'}\"")
        result.append("")
        result.append("然后运行:")
        result.append(f'  bb_summary url="{url or "https://target.com"}" findings="<粘贴所有扫描结果>"')
        result.append("")
        result.append("=" * 60)
        return "\n".join(result)

    # 解析 findings 文本，提取关键信息
    import re

    # 统计各类发现
    stats = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "endpoints": set(),
        "params": set(),
        "tech_stack": set(),
        "waf": set(),
        "auth_required": False,
        "total_payloads": 0,
        "findings_detail": [],
    }

    lines = findings.split("\n")
    for line in lines:
        line_lower = line.lower()

        # 严重程度统计
        if "[!" in line or "[HIGH]" in line.upper() or "高危" in line:
            stats["high"] += 1
            stats["findings_detail"].append(("HIGH", line.strip()))
        elif "[!" in line or "[MEDIUM]" in line.upper() or "中危" in line:
            stats["medium"] += 1
            stats["findings_detail"].append(("MEDIUM", line.strip()))
        elif "[i" in line or "[LOW]" in line.upper() or "低危" in line:
            stats["low"] += 1
            stats["findings_detail"].append(("LOW", line.strip()))

        # AUTH 状态
        if "[AUTH:" in line:
            if "required" in line_lower:
                stats["auth_required"] = True

        # 技术栈
        for tech in ["nginx", "apache", "iis", "tomcat", "cloudflare", "php",
                     "python", "java", "asp.net", "spring", "wordpress", "drupal",
                     "joomla", "thinkphp", "laravel"]:
            if tech in line_lower and ("发现" in line or "识别" in line or "detected" in line):
                stats["tech_stack"].add(tech)

        # WAF
        for waf in ["cloudflare", "阿里云", "腾讯云", "安全狗", "modsecurity"]:
            if waf in line_lower and "waf" in line_lower:
                stats["waf"].add(waf)

        # 端点
        api_m = re.findall(r'(https?://[^\s"\']+(?:api|v1|v2|rest|graphql)[^\s"\']+)', line, re.IGNORECASE)
        for m in api_m:
            stats["endpoints"].add(m)

        # 参数
        param_m = re.findall(r'[?&](\w+)=', line)
        for m in param_m:
            stats["params"].add(m)

        # Payload 数
        payload_m = re.search(r'Payload\s*数[:\s]*(\d+)', line)
        if payload_m:
            stats["total_payloads"] += int(payload_m.group(1))

    # 生成报告
    result.append("一、资产总览")
    result.append("-" * 40)
    if stats["endpoints"]:
        result.append(f"  API 端点: {len(stats['endpoints'])} 个")
    if stats["params"]:
        result.append(f"  发现参数: {', '.join(sorted(stats['params'])[:10])}")
    if stats["tech_stack"]:
        result.append(f"  技术栈: {', '.join(sorted(stats['tech_stack']))}")
    if stats["waf"]:
        result.append(f"  WAF: {', '.join(sorted(stats['waf']))}")
    if stats["auth_required"]:
        result.append(f"  认证: 需要登录")
    else:
        result.append(f"  认证: 无需登录")
    result.append("")

    # 漏洞统计
    result.append("二、漏洞统计")
    result.append("-" * 40)
    total = stats["high"] + stats["medium"] + stats["low"]
    result.append(f"  高危: {stats['high']}")
    result.append(f"  中危: {stats['medium']}")
    result.append(f"  低危: {stats['low']}")
    result.append(f"  总计: {total}")
    result.append("")

    if stats["findings_detail"]:
        result.append("三、详细发现")
        result.append("-" * 40)
        for severity, detail in stats["findings_detail"][:30]:
            result.append(f"  [{severity}] {detail[:120]}")

    result.append("")
    result.append("=" * 60)
    result.append(f"  报告由 Xuanmu Bug Bounty MCP 自动生成")
    result.append("=" * 60)

    return "\n".join(result)
