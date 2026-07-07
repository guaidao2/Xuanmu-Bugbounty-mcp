"""GraphQL 安全检测工具"""

import json
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


# GraphQL introspection 查询
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        type { kind name ofType { kind name } }
      }
    }
    directives { name description locations }
  }
}
"""

# 批量查询攻击 Payload
BATCH_QUERY = """{"query":"query { __typename }","variables":{}}"""

# 深度递归查询
DEEP_RECURSIVE = """
query {
  __schema {
    types {
      fields {
        type {
          fields {
            type {
              fields {
                type { name }
              }
            }
          }
        }
      }
    }
  }
}
"""


async def bb_graphql(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    GraphQL 安全扫描 — Introspection / 批量查询 / 深度递归

    Args:
        url: GraphQL 端点 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        GraphQL 安全分析结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] GraphQL 扫描目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # 1. 确认是 GraphQL 端点
    try:
        probe = await client.post(
            url,
            json_data={"query": "query { __typename }"},
            headers={"Content-Type": "application/json"},
        )
        if probe.status_code == 200 and "__typename" in probe.text:
            results.append("[+] GraphQL 端点确认")
        else:
            results.append("[*] 响应异常（但仍尝试后续检测）")
    except Exception as e:
        results.append(f"[!] 端点探测失败: {e}")
        return "\n".join(results)

    # 2. Introspection 查询
    results.append("")
    results.append("[*] Introspection 查询:")
    try:
        resp = await client.post(
            url,
            json_data={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        if "data" in data and data["data"] and "__schema" in data["data"]:
            schema = data["data"]["__schema"]
            query_type = schema.get("queryType", {}).get("name", "unknown")
            mutation_type = schema.get("mutationType", {}).get("name", "N/A")

            results.append(f"  Query Type: {query_type}")
            results.append(f"  Mutation Type: {mutation_type}")

            # 提取所有查询/变更操作
            queries = []
            mutations = []
            for t in schema.get("types", []):
                if t.get("fields"):
                    for f in t["fields"]:
                        name = f["name"]
                        if name.startswith("__"):
                            continue
                        if t["name"] == query_type:
                            queries.append(name)
                        elif t["name"] == mutation_type:
                            mutations.append(name)

            if queries:
                results.append(f"  [Query] 可用操作 ({len(queries)}):")
                for q in sorted(queries)[:20]:
                    results.append(f"    → {q}")
                if len(queries) > 20:
                    results.append(f"    ... 还有 {len(queries)-20} 个")

            if mutations:
                results.append(f"  [Mutation] 变更操作 ({len(mutations)}):")
                for m in sorted(mutations)[:10]:
                    results.append(f"    → {m}")
                if len(mutations) > 10:
                    results.append(f"    ... 还有 {len(mutations)-10} 个")

            # 检查危险操作
            dangerous_ops = ["__debug", "admin", "delete", "drop", "truncate",
                           "reset", "exec", "eval", "shell", "system"]
            found_danger = [op for op in queries + mutations
                          if any(d in op.lower() for d in dangerous_ops)]
            if found_danger:
                results.append("")
                results.append("  [!] 发现可疑危险操作:")
                for op in found_danger:
                    results.append(f"    → {op}")

            results.append("")
            results.append("  [!] Introspection 已开启 — 攻击者可获取完整 Schema")
        else:
            results.append("  [-] Introspection 已关闭或受限")
    except Exception as e:
        results.append(f"  [!] 查询失败: {e}")

    # 3. 批量查询检测（DoS / 速率滥用）
    results.append("")
    results.append("[*] 批量查询检测:")
    try:
        batch_body = "[" + ",".join([BATCH_QUERY for _ in range(10)]) + "]"
        resp = await client.post(
            url,
            data=batch_body,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            results.append("  [!] 支持批量查询 — 可能存在 DoS 和速率滥用风险")
        else:
            results.append(f"  [-] 批量查询被限制 (HTTP {resp.status_code})")
    except Exception:
        results.append("  [!] 检测失败")

    # 4. 深度递归查询检测
    results.append("")
    results.append("[*] 深度递归查询检测:")
    try:
        resp = await client.post(
            url,
            json_data={"query": DEEP_RECURSIVE},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        results.append(f"  [!] 支持深度递归查询 — 可能存在 DoS 风险 (状态: {resp.status_code})")
    except Exception:
        results.append("  [-] 深度递归请求超时或失败")
        results.append("  [+] 深度递归可能被限制")

    # 安全建议
    results.append("")
    results.append("[*] GraphQL 安全建议:")
    results.append("  - 生产环境关闭 Introspection")
    results.append("  - 限制查询深度和复杂度")
    results.append("  - 禁用批量查询或限制数量")
    results.append("  - 认证 + 速率限制")
    results.append("  - 使用查询白名单 (Persisted Queries)")
    results.append("  - 禁用 __schema 查询")

    return "\n".join(results)
