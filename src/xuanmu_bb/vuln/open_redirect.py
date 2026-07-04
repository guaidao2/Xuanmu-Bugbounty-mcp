"""开放重定向检测工具"""

import asyncio
from typing import Optional

from ..client import HttpClient
from ..data import REDIRECT_PAYLOADS
from ..utils import normalize_url
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


async def bb_open_redirect(
    url: str,
    params: str = "",
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 10,
) -> str:
    """
    开放重定向检测

    Args:
        url: 目标 URL（含参数）
        params: 参数字段名（逗号分隔），默认自动提取
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 单请求超时秒数（默认 10）

    Returns:
        重定向检测结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 开放重定向检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, verify_ssl=False, auth_token=auth_token)

    test_params = [p.strip() for p in params.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())
        # 额外检测常见重定向参数名
        redirect_params = ["url", "redirect", "redirect_url", "redirect_uri",
                          "return", "return_url", "return_uri", "next", "goto",
                          "target", "dest", "destination", "to", "link", "href",
                          "out", "view", "image_url", "image", "img", "pic",
                          "file", "load", "read", "source", "uri", "path",
                          "redirect_to", "redirect_url", "redirect_uri",
                          "redirecturl", "redirecturi", "callback", "cb"]
        # 合并
        for rp in redirect_params:
            if rp not in test_params:
                test_params.append(rp)
        test_params = list(dict.fromkeys(test_params))

    if not test_params:
        results.append("[!] 未找到参数")
        return "\n".join(results)

    # 限制最大测试参数数，避免超时
    if len(test_params) > 20:
        results.append(f"[*] 参数较多 ({len(test_params)}), 限制为前 20 个")
        test_params = test_params[:20]

    findings = []
    sem = asyncio.Semaphore(10)  # 最多 10 并发

    async def _check(param, redirect_url):
        async with sem:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [redirect_url]
                new_qs = urlencode(qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_qs))
                resp = await client.get(new_url, follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location.lower():
                        return {"param": param, "redirect_url": redirect_url,
                                "status": resp.status_code, "location": location[:200]}
            except Exception:
                pass
        return None

    tasks = [_check(p, r) for p in test_params for r in REDIRECT_PAYLOADS]
    done = await asyncio.gather(*tasks)
    findings = [f for f in done if f]

    if not findings:
        results.append("[-] 未检测到开放重定向")
        results.append("")
        results.append("[*] 提示: 部分重定向可能依赖 JavaScript 跳转（Location 不可见）")
        results.append("    人工验证时可尝试: curl -I '<URL>' 查看 Location 头")
    else:
        results.append(f"[!] 发现 {len(findings)} 个开放重定向点:")
        results.append("")
        for f in findings[:15]:
            results.append(f"  参数: {f['param']}")
            results.append(f"  状态码: {f['status']}")
            results.append(f"  Payload: {f['redirect_url']}")
            results.append(f"  Location: {f['location']}")
            results.append("")

    return "\n".join(results)
