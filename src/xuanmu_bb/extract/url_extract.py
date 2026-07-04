"""URL / Endpoint 提取工具"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..client import HttpClient
from ..utils import normalize_url, extract_js_urls, extract_links


async def bb_extract(
    url: str,
    depth: int = 1,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    URL / Endpoint 提取 — 从 HTML 和 JS 中提取链接、API 端点

    Args:
        url: 目标 URL
        depth: 提取深度（1=当前页面, 2=包含引用的JS, 默认1）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        提取的 URL 列表
    """
    url = normalize_url(url)
    base_domain = urlparse(url).netloc

    results = []
    results.append(f"[*] URL 提取目标: {url}")
    results.append(f"[*] 提取深度: {depth}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    all_urls = set()
    js_file_urls = set()

    try:
        resp = await client.get(url)
        html = resp.text
    except Exception as e:
        return f"[!] 请求失败: {e}"

    # 1. 提取页面中的链接
    links = extract_links(html, base_url=url)
    for link in links:
        all_urls.add(link)

    # 2. 提取 JS 文件 URL
    js_urls = extract_js_urls(html, base_url=url)
    for js in js_urls:
        js_file_urls.add(js)
        all_urls.add(js)

    # 3. API 端点正则提取
    endpoint_patterns = [
        r'/api/v[\d]+/[a-zA-Z0-9_/.-]+',
        r'/v[\d]+/[a-zA-Z0-9_/.-]+',
        r'/graphql',
        r'/rest/[a-zA-Z0-9_/.-]+',
        r'/rpc/[a-zA-Z0-9_/.-]+',
    ]
    for pattern in endpoint_patterns:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            endpoint = m.group(0)
            all_urls.add(urljoin(url, endpoint))

    # 4. 如果 depth >= 2，提取 JS 中的内容
    if depth >= 2:
        for js_url in js_file_urls:
            try:
                js_resp = await client.get(js_url, timeout=timeout)
                js_content = js_resp.text

                # 从 JS 中提取 URL
                for m in re.finditer(
                    r'["\']((?:https?://|/)[a-zA-Z0-9_./?=&%-]+)["\']',
                    js_content,
                ):
                    extracted = m.group(1)
                    if extracted.startswith("http"):
                        all_urls.add(extracted)
                    else:
                        all_urls.add(urljoin(url, extracted))

                # 从 JS 中提取 API 端点
                for m in re.finditer(
                    r'["\'](/[a-zA-Z0-9_/.-]*(?:api|v1|v2|v3|rest|graphql|rpc)[a-zA-Z0-9_/.-]*)["\']',
                    js_content,
                    re.IGNORECASE,
                ):
                    all_urls.add(urljoin(url, m.group(1)))
            except Exception:
                pass

    # 5. 分类和输出
    page_urls = sorted([u for u in all_urls if urlparse(u).netloc == base_domain])
    external_urls = sorted([u for u in all_urls if urlparse(u).netloc and urlparse(u).netloc != base_domain])
    endpoints = sorted([u for u in all_urls if any(p in u.lower() for p in ['/api/', '/v1/', '/v2/', '/rest/', '/rpc/', '/graphql'])])

    results.append(f"[*] 总计提取 URL: {len(all_urls)}")
    results.append("")

    if endpoints:
        results.append(f"[✓] API 端点 ({len(endpoints)}):")
        for e in endpoints[:20]:
            results.append(f"  → {e}")
        if len(endpoints) > 20:
            results.append(f"  ... 还有 {len(endpoints)-20} 个")

    results.append("")
    results.append(f"[*] 同域页面 ({len(page_urls)}):")
    for u in page_urls[:15]:
        results.append(f"  → {u}")
    if len(page_urls) > 15:
        results.append(f"  ... 还有 {len(page_urls)-15} 个")

    if js_file_urls:
        results.append("")
        results.append(f"[*] JS 文件 ({len(js_file_urls)}):")
        for js in sorted(js_file_urls):
            results.append(f"  → {js}")

    if external_urls:
        results.append("")
        results.append(f"[*] 外链 ({len(external_urls)}):")
        for e in external_urls[:10]:
            results.append(f"  → {e}")

    return "\n".join(results)
