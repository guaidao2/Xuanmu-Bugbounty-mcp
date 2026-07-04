"""多步骤流程测试工具 — Session 保持 + 请求链"""

import json
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_session(
    steps: str,
    proxy: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """
    多步骤流程测试 — 自动保持 Cookie + 链式请求

    用于测试多步骤业务流中的漏洞:
    - 注册 → 登录 → 越权操作
    - 加购物车 → 改价格 → 下单
    - 创建订单 → 并发取消 → 退款

    Args:
        steps: JSON 格式的步骤列表
            [
              {"method": "POST", "url": "https://target.com/login", "body": "username=admin&password=test"},
              {"method": "GET", "url": "https://target.com/api/profile"},
              {"method": "POST", "url": "https://target.com/api/order", "body": "{\"item\":\"1\"}", "headers": "Content-Type: application/json"}
            ]
        proxy: 代理地址（可选）
        timeout: 单步超时秒数（默认 30）

    Returns:
        每一步的请求和响应详情
    """
    result = []
    result.append("[*] 多步骤流程测试")
    result.append("")

    # 解析步骤
    try:
        step_list = json.loads(steps)
    except (json.JSONDecodeError, TypeError) as e:
        return f"[!] steps 参数格式错误，需要 JSON 数组: {e}"

    if not isinstance(step_list, list) or len(step_list) == 0:
        return "[!] steps 需要是一个非空 JSON 数组"

    # 使用单个 HttpClient 实例保持 Cookie
    client = HttpClient(timeout=timeout, proxy=proxy)

    result.append(f"[*] 步骤数: {len(step_list)}")
    result.append("")

    for i, step in enumerate(step_list, 1):
        method = step.get("method", "GET").upper()
        url = normalize_url(step.get("url", ""))
        body = step.get("body", "")
        headers_str = step.get("headers", "")

        result.append(f"{'='*50}")
        result.append(f"步骤 #{i}: {method} {url}")
        result.append(f"{'='*50}")

        # 解析自定义头
        custom_headers = {}
        if headers_str:
            try:
                custom_headers = json.loads(headers_str)
            except (json.JSONDecodeError, TypeError):
                for line in headers_str.split("\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        custom_headers[k.strip()] = v.strip()

        # 发送请求
        try:
            if method == "GET":
                resp = await client.get(url, headers=custom_headers)
            elif method == "POST":
                # 判断 content-type
                ct = custom_headers.get("Content-Type", "")
                if "json" in ct:
                    try:
                        json_body = json.loads(body)
                        resp = await client.post(url, json_data=json_body, headers=custom_headers)
                    except (json.JSONDecodeError, TypeError):
                        resp = await client.post(url, data=body, headers=custom_headers)
                else:
                    resp = await client.post(url, data=body, headers=custom_headers)
            elif method == "PUT":
                resp = await client.put(url, data=body, headers=custom_headers)
            elif method == "DELETE":
                resp = await client.delete(url, headers=custom_headers)
            else:
                resp = await client.request(method, url, data=body, headers=custom_headers)

            # 输出响应
            result.append(f"  HTTP {resp.status_code} ({len(resp.content)} bytes)")

            # set-cookie
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie:
                result.append(f"  Set-Cookie: {set_cookie[:150]}")

            # 关键响应头
            for h in ["Location", "Content-Type", "X-Request-Id"]:
                if h in resp.headers:
                    result.append(f"  {h}: {resp.headers[h][:100]}")

            # 响应体预览
            body_text = resp.text[:500].replace("\n", " ").strip()
            if body_text:
                result.append(f"  响应体: {body_text[:200]}")

        except Exception as e:
            result.append(f"  [!] 请求异常: {e}")

        result.append("")

    # 汇总
    result.append(f"{'='*50}")
    result.append("[*] 流程完成. 如需检查越权，可使用 bb_idor")
    result.append("[*] 如需检查条件竞争，可使用 bb_race")
    result.append(f"{'='*50}")

    return "\n".join(result)
