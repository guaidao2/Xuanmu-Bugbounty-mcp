"""参数自动发现工具 — 从页面/API/JS 中提取可用参数"""

import json
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urljoin

from ..client import HttpClient
from ..utils import normalize_url


async def bb_param_discover(
    url: str,
    depth: int = 1,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    参数自动发现 — 从页面/API/JS 中提取所有可用参数

    检测内容:
    1. HTML 表单字段（input/textarea/select name）
    2. URL 查询参数
    3. JSON API 字段（从响应体解析）
    4. JavaScript 中的变量和 API 调用
    5. Cookie 参数
    6. 常见参数名猜测（用于模糊测试）

    Args:
        url: 目标 URL
        depth: 提取深度（1=当前页面, 2=含引用的JS, 默认1）
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        发现的参数分类列表
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 参数发现目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.get(url)
        html = resp.text
        status = resp.status_code
        ct = resp.headers.get("Content-Type", "")
    except Exception as e:
        return f"[!] 请求失败: {e}"

    # 检查认证状态
    auth_status = "none"
    if status == 401:
        auth_status = "required (401)"
    elif status == 403:
        auth_status = "required (403)"
    elif status == 200:
        auth_status = "optional (200)"
    results.append(f"[AUTH: {auth_status}] HTTP {status}")
    results.append("")

    discovered = {
        "form_inputs": set(),
        "query_params": set(),
        "json_fields": set(),
        "js_vars": set(),
        "cookie_params": set(),
        "common_params": set(),
        "endpoints": set(),
    }

    # 1. URL 查询参数
    parsed = urlparse(url)
    for k in parse_qs(parsed.query):
        discovered["query_params"].add(k)

    # 2. HTML 表单字段
    for pattern in [
        r'<input[^>]*name=["\']([^"\']*)["\']',
        r'<textarea[^>]*name=["\']([^"\']*)["\']',
        r'<select[^>]*name=["\']([^"\']*)["\']',
        r'<form[^>]*name=["\']([^"\']*)["\']',
    ]:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            discovered["form_inputs"].add(m.group(1))

    # 3. 从表单 action 中提取 endpoint
    for m in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE):
        action = m.group(1)
        if action and not action.startswith(("#", "javascript:")):
            discovered["endpoints"].add(action)

    # 4. JSON 响应解析
    if "json" in ct:
        try:
            data = json.loads(html)
            def extract_keys(obj, prefix=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        full_key = f"{prefix}.{k}" if prefix else k
                        discovered["json_fields"].add(full_key)
                        if isinstance(v, (dict, list)):
                            extract_keys(v, full_key)
                elif isinstance(obj, list) and obj:
                    extract_keys(obj[0], f"{prefix}[]")
            extract_keys(data)
        except (json.JSONDecodeError, ValueError):
            pass

    # 5. JavaScript 变量和 API 调用
    # 提取 var/let/const 变量
    for m in re.finditer(r'(?:var|let|const)\s+(\w+)\s*=', html):
        discovered["js_vars"].add(m.group(1))

    # 提取 JS 中的 API 端点
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_/.-]*(?:api|v1|v2|v3|rest|graphql|rpc)[a-zA-Z0-9_/.-]*)["\']', html, re.IGNORECASE):
        discovered["endpoints"].add(m.group(1))

    # 提取 fetch/ajax/axios 调用中的 URL
    for m in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete)|ajax|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        discovered["endpoints"].add(m.group(1))

    # 6. Cookie 参数
    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        for cookie_part in set_cookie.split(";"):
            if "=" in cookie_part:
                name = cookie_part.split("=")[0].strip()
                if name.lower() not in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
                    discovered["cookie_params"].add(name)

    # 7. 常见参数名（用于模糊测试建议）
    common_params = [
        "id", "page", "page_size", "limit", "offset", "sort", "order",
        "search", "q", "query", "keyword", "key", "value",
        "token", "access_token", "api_key", "secret",
        "username", "password", "email", "phone", "mobile",
        "name", "title", "desc", "description", "content",
        "type", "status", "state", "action", "method",
        "url", "redirect", "next", "goto", "return", "callback",
        "file", "filename", "path", "dir", "src", "href",
        "lang", "locale", "theme", "mode", "debug",
        "timestamp", "date", "time", "version",
        "callback", "jsonp", "format", "_",
    ]
    discovered["common_params"] = set(common_params)

    # 8. 如果 depth >= 2，提取引用的 JS 文件
    if depth >= 2:
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']*)["\']', html, re.IGNORECASE):
            js_url = m.group(1)
            if js_url:
                full_js_url = urljoin(url, js_url)
                try:
                    js_resp = await client.get(full_js_url, timeout=timeout)
                    js_content = js_resp.text
                    # 从 JS 提取变量
                    for vm in re.finditer(r'(?:var|let|const)\s+(\w+)\s*=', js_content):
                        discovered["js_vars"].add(vm.group(1))
                    # 从 JS 提取 API 路径
                    for am in re.finditer(r'["\'](/[a-zA-Z0-9_/.-]+)["\']', js_content):
                        path = am.group(1)
                        if any(p in path.lower() for p in ["/api/", "/v1/", "/v2/", "/rest/"]):
                            discovered["endpoints"].add(path)
                except Exception:
                    pass

    # === 输出 ===
    results.append(f"=== 参数发现结果 ===")
    results.append("")

    if discovered["query_params"]:
        results.append(f"[URL 查询参数] ({len(discovered['query_params'])}):")
        for p in sorted(discovered["query_params"]):
            results.append(f"  ?{p}=<value>")
        results.append("")

    if discovered["form_inputs"]:
        results.append(f"[表单字段] ({len(discovered['form_inputs'])}):")
        for p in sorted(discovered["form_inputs"]):
            results.append(f"  {p}")
        results.append("")

    if discovered["json_fields"]:
        results.append(f"[JSON 字段] ({len(discovered['json_fields'])}):")
        for p in sorted(discovered["json_fields"])[:20]:
            results.append(f"  {p}")
        if len(discovered["json_fields"]) > 20:
            results.append(f"  ... 还有 {len(discovered['json_fields'])-20} 个")
        results.append("")

    if discovered["js_vars"]:
        results.append(f"[JS 变量] ({len(discovered['js_vars'])}):")
        for p in sorted(discovered["js_vars"])[:15]:
            results.append(f"  {p}")
        if len(discovered["js_vars"]) > 15:
            results.append(f"  ... 还有 {len(discovered['js_vars'])-15} 个")
        results.append("")

    if discovered["endpoints"]:
        results.append(f"[发现的端点] ({len(discovered['endpoints'])}):")
        for p in sorted(discovered["endpoints"])[:15]:
            results.append(f"  {p}")
        results.append("")

    if discovered["cookie_params"]:
        results.append(f"[Cookie 参数] ({len(discovered['cookie_params'])}):")
        for p in sorted(discovered["cookie_params"]):
            results.append(f"  {p}")
        results.append("")

    # 常用参数推荐
    results.append(f"[推荐测试参数] — 可用于 bb_sqli / bb_xss / bb_ssti 等:")
    all_found = discovered["form_inputs"] | discovered["query_params"] | discovered["json_fields"]
    if all_found:
        results.append(f"  params=\"{','.join(sorted(all_found)[:10])}\"")
    else:
        results.append(f"  页面未发现参数，可尝试常见参数:")
        results.append(f"  params=\"{','.join(common_params[:10])}\"")

    results.append("")
    results.append("[*] 建议的下一步:")
    if all_found:
        params_str = ",".join(sorted(all_found)[:8])
        results.append(f"  bb_sqli url=\"{url}\" params=\"{params_str}\" auth_token=\"<token>\"")
        results.append(f"  bb_xss  url=\"{url}\" params=\"{params_str}\" auth_token=\"<token>\"")
    results.append(f"  bb_dir_scan url=\"{url}\" auth_token=\"<token>\"")

    return "\n".join(results)
