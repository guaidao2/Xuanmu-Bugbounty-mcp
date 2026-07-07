"""JS 深度分析工具 — API路由/Sourcemap/硬编码密钥/SPA路由/WebSocket"""

import json
import re
from typing import Optional
from urllib.parse import urljoin

from ..client import HttpClient
from ..utils import normalize_url, extract_js_urls


# ============================================================
# 增强正则模式
# ============================================================

# API 路由 — 更全面的模式
API_PATTERNS = [
    r'["\'`]((?:/[a-zA-Z0-9_.-]+)+(?:/api|/v[1-9]|/rest|/graphql|/rpc|/swagger|/sdk)[a-zA-Z0-9_/.\-]*)["\'`]',
    r'["\'`](/[a-zA-Z0-9_/.-]*(?:api|v[1-9]|rest|graphql|rpc|swagger)[a-zA-Z0-9_/.\-]*)["\'`]',
    r'["\'`](https?://[a-zA-Z0-9_.-]+/(?:api|v[1-9]|rest|graphql)[a-zA-Z0-9_/.\-]*)["\'`]',
    # 拼接模式: '/api/' + id + '/detail'
    r"['\"`](/[a-zA-Z0-9_/.-]*api/[a-zA-Z0-9_/.\-]*)['\"`]",
    # fetch/axios 调用
    r"(?:fetch|axios|ajax|\.get|\.post|\.put|\.delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
]

# SPA 路由 — Vue/React/Angular 路由定义
SPA_PATTERNS = [
    r'(?:path|route|component|name)\s*:\s*["\'`]([a-zA-Z0-9_/\-]+)["\'`]',
    r'(?:router\.push|router\.replace|navigateTo|navigate)\s*\(\s*["\'`]([a-zA-Z0-9_/\-]+)["\'`]',
    r"(?:path|route)\s*:\s*['\"`](/[a-zA-Z0-9_/\-]*)['\"`]",
    # Vue Router routes: { path: '/user/:id', component: User }
    r"path:\s*['\"`](/[a-zA-Z0-9_/\-:]*)['\"`]",
    # React Router: <Route path="/admin" />
    r"Route\s+path=['\"`](/[a-zA-Z0-9_/\-]*)['\"`]",
]

# WebSocket
WS_PATTERNS = [
    r'(?:new\s+WebSocket|wss?://|connect\s*\(\s*["\'`])([^"\'`\s]+)',
    r'["\'`](wss?://[a-zA-Z0-9_.\-/]+)["\'`]',
    r"['\"`](/ws[a-zA-Z0-9_/\-]*)['\"`]",
    r"(?:socket|ws)\s*:\s*['\"`]([^'\"`]+)['\"`]",
]

# 密钥 — 扩展列表
SECRET_PATTERNS = [
    ("AWS Access Key", r'(?i)(AKIA[0-9A-Z]{16})'),
    ("AWS Secret Key", r'(?i)([^A-Za-z0-9+/=][A-Za-z0-9+/=]{40}[^A-Za-z0-9+/=])'),
    ("Google API Key", r'(?i)(AIza[0-9A-Za-z_-]{35})'),
    ("Firebase DB URL", r'(?i)([a-zA-Z0-9-]+\.firebaseio\.com)'),
    ("Firebase App", r'(?i)([a-zA-Z0-9-]+\.firebaseapp\.com)'),
    ("Stripe Live Key", r'(?i)(sk_live_[0-9a-zA-Z]+|pk_live_[0-9a-zA-Z]+)'),
    ("Stripe Test Key", r'(?i)(sk_test_[0-9a-zA-Z]+|pk_test_[0-9a-zA-Z]+)'),
    ("GitHub Token", r'(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|gho_[a-zA-Z0-9]{36})'),
    ("Slack Token", r'(?i)(xox[baprs]-[0-9a-zA-Z-]{10,})'),
    ("JWT Token", r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),
    ("阿里云 AccessKey", r'(?i)(LTAI[a-zA-Z0-9]{12,})'),
    ("腾讯云 SecretId", r'(?i)(AKID[a-zA-Z0-9]{15,})'),
    ("Mapbox Token", r'(?i)(pk\.eyJ[a-zA-Z0-9_-]{30,})'),
    ("Heroku API Key", r'(?i)([hH][eE][rR][oO][kK][uU]\s*:\s*[a-zA-Z0-9-]{20,})'),
    ("MongoDB URI", r'(?i)(mongodb(?:\+srv)?://[a-zA-Z0-9_:@.\-]+)'),
    ("MySQL URI", r'(?i)(mysql://[a-zA-Z0-9_:@.\-]+)'),
    ("Redis URI", r'(?i)(redis://[a-zA-Z0-9_:@.\-]+)'),
    ("PostgreSQL URI", r'(?i)(postgres(?:ql)?://[a-zA-Z0-9_:@.\-]+)'),
    ("Docker Auth", r'(?i)(\{\"auths\":\s*\{)'),
    ("Private Key", r'-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PRIVATE)\s?KEY-----'),
    ("npm Token", r'(?i)(//npm\.(?:pkg|github)\.com/:_authToken=[a-zA-Z0-9-]+)'),
]

# Sourcemap
SOURCE_PATTERNS = [
    r'(?:sourceMappingURL|//# sourceMappingURL=)([^\s"\'`]+)',
    r'\.map["\'`]',
]

# 云服务
CLOUD_PATTERNS = [
    ("AWS S3 Bucket", r'(?i)([a-zA-Z0-9.-]+\.s3\.amazonaws\.com)'),
    ("AWS CloudFront", r'(?i)([a-zA-Z0-9.-]+\.cloudfront\.net)'),
    ("阿里云 OSS", r'(?i)([a-zA-Z0-9.-]+\.oss-[a-z]+\.aliyuncs\.com)'),
    ("腾讯云 COS", r'(?i)([a-zA-Z0-9.-]+\.cos\.[a-z]+\.myqcloud\.com)'),
    ("Azure Blob", r'(?i)([a-zA-Z0-9-]+\.blob\.core\.windows\.net)'),
    ("Azure CDN", r'(?i)([a-zA-Z0-9-]+\.azureedge\.net)'),
    ("Firebase", r'(?i)([a-zA-Z0-9-]+\.firebase(?:app|io)\.com)'),
    ("Vercel", r'(?i)([a-zA-Z0-9-]+\.vercel\.app)'),
    ("Netlify", r'(?i)([a-zA-Z0-9-]+\.netlify\.app)'),
]

# 内联 JS 提取
INLINE_JS = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
# JS 变量/配置对象
CONFIG_OBJECT = re.compile(r'(?:var|let|const|window\.)\s*(\w+)\s*=\s*\{([^}]+)\}', re.IGNORECASE)


async def bb_js_analyze(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    JS 深度分析 — 从页面/内联JS/JS文件中提取所有可用信息

    检测内容:
    1. API 路由 — 所有 /api/v1/、/rest/、fetch/axios 调用
    2. Sourcemap — .map 文件泄露检测
    3. 硬编码密钥 — AWS/GitHub/Stripe/JWT/数据库连接串
    4. SPA 路由 — Vue/React/Angular 路由定义
    5. WebSocket 端点 — ws:// 和 new WebSocket() 调用
    6. 云服务配置 — S3/OSS/Firebase/Vercel/Netlify
    7. 内联 JS — 页面中的 inline script 内容
    8. 配置对象 — 暴露的 API endpoint 配置

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

    # 收集所有分析源
    content_sources = []

    # 1. HTML 本身
    content_sources.append(("HTML", html))

    # 2. 内联 JS
    inline_scripts = []
    for m in INLINE_JS.finditer(html):
        js_code = m.group(1).strip()
        if js_code and len(js_code) > 20:
            inline_scripts.append(js_code)
            content_sources.append(("Inline JS", js_code))

    if inline_scripts:
        results.append(f"[*] 发现 {len(inline_scripts)} 个内联 JS 块")
    else:
        results.append("[*] 未发现内联 JS")

    # 3. JS 文件
    js_urls = extract_js_urls(html, base_url=url)
    if js_urls:
        results.append(f"[*] 发现 {len(js_urls)} 个外部 JS 文件")

        for js_url in js_urls:
            try:
                js_resp = await client.get(js_url)
                js_content = js_resp.text
                if js_content:
                    content_sources.append((f"JS: {js_url.split('/')[-1]}", js_content))
            except Exception:
                pass
    else:
        results.append("[*] 未发现外部 JS 文件")

    results.append("")

    # ============================================================
    # 全面分析
    # ============================================================
    findings = {
        "api_routes": set(),
        "sourcemaps": set(),
        "secrets": [],
        "spa_routes": set(),
        "websockets": set(),
        "cloud": [],
        "config_objects": [],
    }

    for source_name, content in content_sources:
        if not content:
            continue

        # ---- API 路由 ----
        for pattern in API_PATTERNS:
            for m in re.finditer(pattern, content):
                route = m.group(1)
                if len(route) > 4 and route not in ('/', '//'):
                    findings["api_routes"].add(route)

        # ---- SPA 路由 ----
        for pattern in SPA_PATTERNS:
            for m in re.finditer(pattern, content):
                route = m.group(1)
                if len(route) > 1 and route not in ('/', '/:id', '/:slug'):
                    findings["spa_routes"].add(route)

        # ---- WebSocket ----
        for pattern in WS_PATTERNS:
            for m in re.finditer(pattern, content):
                ws = m.group(1)
                if len(ws) > 3:
                    findings["websockets"].add(ws)

        # ---- 密钥 ----
        for name, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                val = m.group(0).strip()
                masked = val[:20] + "****" + val[-10:] if len(val) > 35 else val
                findings["secrets"].append({"type": name, "value": masked, "from": source_name})

        # ---- 云服务 ----
        for name, pattern in CLOUD_PATTERNS:
            for m in re.finditer(pattern, content):
                findings["cloud"].append({"type": name, "value": m.group(0), "from": source_name})

        # ---- Sourcemap ----
        for pattern in SOURCE_PATTERNS:
            for m in re.finditer(pattern, content):
                sm = m.group(0).strip().rstrip('"\'`')
                findings["sourcemaps"].add(sm)

        # ---- 配置对象 ----
        for m in CONFIG_OBJECT.finditer(content):
            obj_name = m.group(1)
            obj_body = m.group(2)
            if any(kw in obj_body for kw in ['api', 'url', 'endpoint', 'key', 'token', 'secret']):
                findings["config_objects"].append({
                    "name": obj_name,
                    "content": obj_body[:200],
                })

    # ============================================================
    # 去重
    # ============================================================
    seen_secrets = set()
    unique_secrets = []
    for s in findings["secrets"]:
        key = (s["type"], s["value"][:30])
        if key not in seen_secrets:
            seen_secrets.add(key)
            unique_secrets.append(s)
    findings["secrets"] = unique_secrets

    seen_cloud = set()
    unique_cloud = []
    for c in findings["cloud"]:
        key = (c["type"], c["value"])
        if key not in seen_cloud:
            seen_cloud.add(key)
            unique_cloud.append(c)
    findings["cloud"] = unique_cloud

    # ============================================================
    # 输出
    # ============================================================
    has_any = any([
        findings["api_routes"],
        findings["sourcemaps"],
        findings["secrets"],
        findings["spa_routes"],
        findings["websockets"],
        findings["cloud"],
        findings["config_objects"],
    ])

    # ---- API 路由 ----
    if findings["api_routes"]:
        # 按域名分组
        external = sorted([r for r in findings["api_routes"] if r.startswith("http")])
        internal = sorted([r for r in findings["api_routes"] if not r.startswith("http")])
        results.append(f"[API 路由] ({len(findings['api_routes'])} 个):")
        if external:
            for r in external[:15]:
                results.append(f"  - {r}")
        if internal:
            for r in internal[:20]:
                results.append(f"  📁 {r}")
        results.append("")

    # ---- Sourcemap ----
    if findings["sourcemaps"]:
        results.append(f"[Sourcemap 泄露] ({len(findings['sourcemaps'])}):")
        for sm in sorted(findings["sourcemaps"])[:10]:
            results.append(f"  [!] {sm}")
        results.append("  → 访问 .map 文件可获取完整源码!")
        results.append("")

    # ---- 密钥 ----
    if findings["secrets"]:
        results.append(f"[硬编码密钥] ({len(findings['secrets'])}):")
        for s in findings["secrets"][:15]:
            results.append(f"  🔑 [{s['type']}] {s['value']} ({s['from']})")
        results.append("")

    # ---- SPA 路由 ----
    if findings["spa_routes"]:
        results.append(f"[SPA 隐藏路由] ({len(findings['spa_routes'])}):")
        for r in sorted(findings["spa_routes"])[:15]:
            results.append(f"  🚪 {r}")
        results.append("")

    # ---- WebSocket ----
    if findings["websockets"]:
        results.append(f"[WebSocket 端点] ({len(findings['websockets'])}):")
        for ws in findings["websockets"]:
            results.append(f"  - {ws}")
        results.append("")

    # ---- 云服务 ----
    if findings["cloud"]:
        results.append(f"[云服务配置] ({len(findings['cloud'])}):")
        for c in findings["cloud"][:10]:
            results.append(f"  [cloud] [{c['type']}] {c['value']}")
        results.append("")

    # ---- 配置对象 ----
    if findings["config_objects"]:
        results.append(f"[配置对象] ({len(findings['config_objects'])}):")
        for obj in findings["config_objects"][:5]:
            results.append(f"  [config] {obj['name']} = {obj['content'][:150]}")
        results.append("")

    # ---- 无结果时兜底 ----
    if not has_any:
        results.append("[-] 自动分析未发现有效信息")
        results.append("")
        results.append("[*] 建议手动检查:")
        results.append("  1. 打开浏览器开发者工具 → Sources 面板")
        results.append("  2. 搜索 'api', 'token', 'secret', 'key' 关键词")
        results.append("  3. 检查 .map 文件: 在 JS URL 后加 .map")

    # ---- JS 文件摘要 ----
    if js_urls:
        results.append(f"[JS 文件摘要] ({len(js_urls)} 个):")
        for js_url in js_urls:
            try:
                js_resp = await client.get(js_url)
                size = len(js_resp.text)
                preview = js_resp.text[:100].replace("\n", " ").strip()
                results.append(f"  📄 {js_url.split('/')[-1]} ({size:,} bytes)")
                if preview:
                    results.append(f"    {preview}")
            except Exception:
                results.append(f"  📄 {js_url.split('/')[-1]} (获取失败)")

    return "\n".join(results)
