"""JS 深度分析工具 — API路由/Sourcemap/硬编码/SPA路由"""

import json
import re
from typing import Optional
from urllib.parse import urljoin

from ..client import HttpClient
from ..utils import normalize_url, extract_js_urls


async def bb_js_analyze(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    JS 深度分析 — 从页面和 JS 文件中提取 API 路由/隐藏端点/硬编码密钥/Sourcemap/SPA 路由

    检测内容:
    1. API 路由提取 — /api/v1/, /graphql, /rest/ 等
    2. Sourcemap 检测 — .map 文件泄露源码
    3. 硬编码密钥 — API Key / Secret / Token
    4. SPA 路由表 — Vue/React Router 隐藏页面
    5. WebSocket 端点 — new WebSocket() / ws://
    6. 云服务配置 — Firebase / AWS Cognito / 阿里云 OSS

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        JS 深度分析结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] JS 深度分析目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # 获取页面
    try:
        resp = await client.get(url)
        html = resp.text
    except Exception as e:
        return f"[!] 页面获取失败: {e}"

    # 提取所有 JS URL
    js_urls = extract_js_urls(html, base_url=url)
    results.append(f"[*] 发现 {len(js_urls)} 个 JS 文件")
    results.append("")

    findings = {
        "api_routes": set(),
        "sourcemaps": set(),
        "hardcoded_secrets": [],
        "spa_routes": set(),
        "websocket_urls": set(),
        "cloud_configs": [],
    }

    # 正则模式
    API_ROUTE_PATTERN = re.compile(
        r'["\']((?:/[a-zA-Z0-9_./-]+)?(?:api|v[1-9]|rest|graphql|rpc|swagger|sdk)[a-zA-Z0-9_/.-]*)["\']',
        re.IGNORECASE,
    )
    SPA_ROUTE_PATTERN = re.compile(
        r'(?:path|route|component|name)\s*:\s*["\']([a-zA-Z0-9_/-]+)["\']',
        re.IGNORECASE,
    )
    WEBSOCKET_PATTERN = re.compile(
        r'(?:new\s+WebSocket|wss?://|connect\s*\(\s*["\'])([^"\']+)',
        re.IGNORECASE,
    )
    SECRET_PATTERNS = [
        ("AWS Key", r'(?i)(AKIA[0-9A-Z]{16})'),
        ("Firebase URL", r'(?i)([a-zA-Z0-9-]+\.firebaseio\.com)'),
        ("Firebase API Key", r'(?i)(AIza[0-9A-Za-z_-]{35})'),
        ("Google API Key", r'(?i)(AIza[0-9A-Za-z_-]{35})'),
        ("Stripe Key", r'(?i)(sk_live_[0-9a-zA-Z]+|pk_live_[0-9a-zA-Z]+)'),
        ("GitHub Token", r'(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})'),
        ("Slack Token", r'(?i)(xox[baprs]-[0-9a-zA-Z-]+)'),
        ("JWT Token", r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),
        ("阿里云 AccessKey", r'(?i)(LTAI[a-zA-Z0-9]{12,})'),
        ("腾讯云 SecretId", r'(?i)(AKID[a-zA-Z0-9]{15,})'),
    ]
    SOURCEMAP_PATTERN = re.compile(
        r'(?:sourceMappingURL|//# sourceMappingURL=)([^\s]+)',
        re.IGNORECASE,
    )
    CLOUD_PATTERNS = [
        ("AWS S3", r'(?i)([a-zA-Z0-9.-]+\.s3\.amazonaws\.com)'),
        ("AWS CloudFront", r'(?i)([a-zA-Z0-9.-]+\.cloudfront\.net)'),
        ("阿里云 OSS", r'(?i)([a-zA-Z0-9.-]+\.oss-[a-z]+\.aliyuncs\.com)'),
        ("腾讯云 COS", r'(?i)([a-zA-Z0-9.-]+\.cos\.[a-z]+\.myqcloud\.com)'),
        ("Azure Blob", r'(?i)([a-zA-Z0-9-]+\.blob\.core\.windows\.net)'),
        ("Firebase Auth", r'(?i)([a-zA-Z0-9-]+\.firebaseapp\.com)'),
    ]

    # 分析页面 HTML
    content_sources = [("HTML", html)]

    # 获取并分析每个 JS 文件
    for js_url in js_urls:
        try:
            js_resp = await client.get(js_url, timeout=timeout)
            js_content = js_resp.text
            content_sources.append((f"JS: {js_url.split('/')[-1][:30]}", js_content))

            # Sourcemap 检测
            for m in SOURCEMAP_PATTERN.finditer(js_content):
                sm_path = m.group(1)
                full_sm_url = urljoin(js_url, sm_path)
                findings["sourcemaps"].add(full_sm_url)

        except Exception:
            pass

    # 全面扫描所有内容源
    for source_name, content in content_sources:
        # API 路由
        for m in API_ROUTE_PATTERN.finditer(content):
            route = m.group(1)
            if len(route) > 3:
                findings["api_routes"].add(route)

        # SPA 路由
        for m in SPA_ROUTE_PATTERN.finditer(content):
            route = m.group(1)
            if len(route) > 1 and "/" in route:
                findings["spa_routes"].add(route)

        # WebSocket
        for m in WEBSOCKET_PATTERN.finditer(content):
            ws_url = m.group(1)
            if len(ws_url) > 5:
                findings["websocket_urls"].add(ws_url)

        # 密钥
        for secret_name, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                match = m.group(0)
                findings["hardcoded_secrets"].append({
                    "type": secret_name,
                    "value": match[:20] + "****" + match[-10:] if len(match) > 35 else match,
                    "source": source_name,
                })

        # 云服务
        for cloud_name, pattern in CLOUD_PATTERNS:
            for m in re.finditer(pattern, content):
                findings["cloud_configs"].append({
                    "type": cloud_name,
                    "value": m.group(0),
                    "source": source_name,
                })

    # ===== 输出去重 =====
    unique_secrets = {}
    for s in findings["hardcoded_secrets"]:
        key = (s["type"], s["value"][:30])
        if key not in unique_secrets:
            unique_secrets[key] = s
    findings["hardcoded_secrets"] = list(unique_secrets.values())

    # API 路由
    if findings["api_routes"]:
        api_list = sorted(findings["api_routes"])
        results.append(f"[API 路由] ({len(api_list)} 个):")
        for route in api_list[:25]:
            results.append(f"  → {route}")
        if len(api_list) > 25:
            results.append(f"  ... 还有 {len(api_list)-25} 个")
        results.append("")

    # Sourcemap
    if findings["sourcemaps"]:
        results.append(f"[Sourcemap 泄露] ({len(findings['sourcemaps'])} 个):")
        for sm in sorted(findings["sourcemaps"]):
            results.append(f"  ⚠️ {sm}")
        results.append("  → 访问 .map 文件可能获取完整源码!")
        results.append("")

    # 硬编码密钥
    if findings["hardcoded_secrets"]:
        results.append(f"[硬编码密钥] ({len(findings['hardcoded_secrets'])} 个):")
        for s in findings["hardcoded_secrets"][:10]:
            results.append(f"  ⚠️ [{s['type']}] {s['value']} [{s['source']}]")
        if len(findings["hardcoded_secrets"]) > 10:
            results.append(f"  ... 还有 {len(findings['hardcoded_secrets'])-10} 个")
        results.append("")

    # SPA 路由
    if findings["spa_routes"]:
        results.append(f"[SPA 隐藏路由] ({len(findings['spa_routes'])} 个):")
        for route in sorted(findings["spa_routes"])[:15]:
            results.append(f"  → {route}")
        results.append("")

    # WebSocket
    if findings["websocket_urls"]:
        results.append(f"[WebSocket 端点] ({len(findings['websocket_urls'])} 个):")
        for ws in sorted(findings["websocket_urls"]):
            results.append(f"  → {ws}")
        results.append("")

    # 云服务
    if findings["cloud_configs"]:
        results.append(f"[云服务配置] ({len(findings['cloud_configs'])} 个):")
        uniq_cloud = {}
        for c in findings["cloud_configs"]:
            key = (c["type"], c["value"])
            if key not in uniq_cloud:
                uniq_cloud[key] = c
        for c in list(uniq_cloud.values())[:10]:
            results.append(f"  → [{c['type']}] {c['value']}")
        results.append("")

    if not any(findings.values()):
        results.append("[-] 自动分析未发现有效信息")
        results.append("")
        results.append("[*] JS 文件内容预览:")
        results.append("    尝试手动检查以下 JS 文件中的硬编码内容:")
        for js_url in js_urls:
            try:
                js_resp = await client.get(js_url, timeout=timeout)
                js_content = js_resp.text[:300].replace(chr(10), " ").strip()
                results.append(f"  {js_url} ({len(js_resp.text)} bytes)")
                if js_content:
                    results.append(f"    → {js_content[:150]}")
            except Exception:
                results.append(f"  {js_url} (获取失败)")

    return "\n".join(results)
