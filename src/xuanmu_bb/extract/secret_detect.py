"""敏感信息泄露检测工具"""

import re
from typing import Optional

from ..client import HttpClient
from ..data import SECRET_PATTERNS
from ..utils import normalize_url, extract_js_urls


async def bb_secrets(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
    check_js: bool = True,
) -> str:
    """
    敏感信息泄露检测 — 从页面/JS/响应中检测 Key/Token/密码等

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）
        check_js: 是否深入分析 JS 文件（默认 True）

    Returns:
        检测到的敏感信息列表
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 敏感信息检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    sources_to_check = []
    try:
        resp = await client.get(url)
        sources_to_check.append(("HTML", resp.text))
        content_type = resp.headers.get("Content-Type", "")
        results.append(f"[*] 状态: {resp.status_code} | Content-Type: {content_type}")

        # 提取 JS 文件
        if check_js:
            js_urls = extract_js_urls(resp.text, base_url=url)
            for js_url in js_urls[:5]:  # 最多检查 5 个 JS
                try:
                    js_resp = await client.get(js_url, timeout=timeout)
                    sources_to_check.append((f"JS: {js_url.split('/')[-1]}", js_resp.text))
                except Exception:
                    pass
    except Exception as e:
        return f"[!] 请求失败: {e}"

    # 在全部内容中检测
    all_findings = []
    seen = set()

    for source_name, content in sources_to_check:
        for secret_name, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                match_text = m.group(0)
                # 去重
                key = f"{secret_name}:{match_text[:50]}"
                if key not in seen:
                    seen.add(key)
                    # 脱敏处理
                    masked = match_text[:20] + "****" + match_text[-10:] if len(match_text) > 35 else match_text
                    all_findings.append({
                        "type": secret_name,
                        "match": masked,
                        "source": source_name,
                    })

    # 额外检测注释中的敏感信息
    for source_name, content in sources_to_check:
        # HTML/JS 注释
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        js_comments = re.findall(r'//(.*?)$', content, re.MULTILINE)
        for comment in comments + js_comments:
            comment = comment.strip()
            if any(kw in comment.lower() for kw in
                   ["todo", "fixme", "hack", "bug", "password", "key",
                    "secret", "token", "admin", "root", "test", "debug"]):
                if len(comment) > 10 and comment not in seen:
                    seen.add(comment[:50])
                    all_findings.append({
                        "type": "注释泄露",
                        "match": comment[:200],
                        "source": source_name,
                    })

    if not all_findings:
        results.append("[✓] 未检测到敏感信息泄露")
    else:
        results.append(f"[!] 发现 {len(all_findings)} 处敏感信息:")
        results.append("")

        # 按类型分组
        by_type = {}
        for f in all_findings:
            by_type.setdefault(f["type"], []).append(f)

        for secret_type, items in sorted(by_type.items()):
            results.append(f"  [{secret_type}] ({len(items)} 处)")
            for item in items[:5]:
                results.append(f"    → {item['match']} [{item['source']}]")
            if len(items) > 5:
                results.append(f"    ... 还有 {len(items)-5} 处")
            results.append("")

    # 安全建议
    results.append("[*] 安全建议:")
    results.append("  ✅ 不要在页面/JS 中硬编码凭据")
    results.append("  ✅ 使用环境变量或标准密钥管理服务")
    results.append("  ✅ 删除生产环境的调试注释")
    results.append("  ✅ 对 JS 文件启用 SourceMap 控制")

    return "\n".join(results)
