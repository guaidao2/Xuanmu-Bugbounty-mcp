"""漏洞报告生成工具"""

import json
from datetime import datetime
from typing import Optional


# 漏洞类型及描述
VULN_DESCRIPTIONS = {
    "xss": {
        "name": "跨站脚本攻击 (XSS)",
        "risk": "中危",
        "description": "攻击者可以在受害者的浏览器中执行任意 JavaScript 代码，窃取 Cookie、会话令牌或其他敏感信息。",
        "fix": "1. 对用户输入进行 HTML 实体编码\n2. 使用 CSP 限制资源加载\n3. 设置 X-XSS-Protection 和 X-Content-Type-Options 头",
    },
    "sqli": {
        "name": "SQL 注入 (SQL Injection)",
        "risk": "高危",
        "description": "攻击者可以通过注入恶意的 SQL 语句，绕过认证、读取或修改数据库中的敏感数据。",
        "fix": "1. 使用参数化查询 (Prepared Statement)\n2. 对用户输入进行严格的类型校验\n3. 最小化数据库账户权限",
    },
    "ssrf": {
        "name": "服务端请求伪造 (SSRF)",
        "risk": "高危",
        "description": "攻击者可以强制服务端向任意地址发起请求，可能访问内部网络资源或云元数据接口。",
        "fix": "1. 对 URL 参数进行白名单校验\n2. 禁止访问内网 IP 段\n3. 禁用不必要的协议 (file:/// dict:// gopher://)",
    },
    "ssti": {
        "name": "服务端模板注入 (SSTI)",
        "risk": "高危",
        "description": "攻击者可以通过注入模板表达式，在服务端执行任意代码或读取敏感信息。",
        "fix": "1. 不要在模板中渲染用户输入\n2. 使用沙箱模板引擎\n3. 对模板语法进行转义",
    },
    "cmdi": {
        "name": "命令注入 (Command Injection)",
        "risk": "高危",
        "description": "攻击者可以在服务端执行任意系统命令，获取服务器控制权。",
        "fix": "1. 避免直接拼接命令字符串\n2. 使用白名单校验输入\n3. 使用安全的 API 替代系统命令调用",
    },
    "cors": {
        "name": "CORS 跨域配置缺陷",
        "risk": "中危",
        "description": "CORS 配置不当可能导致攻击者跨域读取敏感资源。",
        "fix": "1. 避免使用 Access-Control-Allow-Origin: *\n2. 不要直接反射 Origin 头\n3. 敏感接口限制特定 Origin",
    },
    "idor": {
        "name": "越权访问 (IDOR)",
        "risk": "高危",
        "description": "攻击者可以通过修改请求参数访问其他用户的资源或数据。",
        "fix": "1. 实现严格的权限校验\n2. 使用不可预测的资源 ID（UUID）\n3. 服务端二次鉴权",
    },
    "lfi": {
        "name": "本地文件包含 (LFI / Path Traversal)",
        "risk": "高危",
        "description": "攻击者可以读取服务器上的任意文件，可能导致源代码泄露或敏感数据暴露。",
        "fix": "1. 对文件路径进行白名单校验\n2. 过滤 ../ 等路径遍历字符\n3. 使用固定文件映射表",
    },
    "xxe": {
        "name": "XML 外部实体注入 (XXE)",
        "risk": "高危",
        "description": "攻击者可以利用 XML 解析器读取服务器文件、内网探测或造成 DoS。",
        "fix": "1. 禁用 XML 外部实体解析\n2. 使用 JSON 替代 XML\n3. 升级 XML 解析库到安全版本",
    },
    "host_inject": {
        "name": "Host 头注入",
        "risk": "中危",
        "description": "攻击者可以构造恶意的 Host 头，可能导致密码重置投毒或缓存污染。",
        "fix": "1. 不直接使用 Host 头生成链接\n2. 使用固定的 ServerName 配置\n3. 校验 Host 头的合法性",
    },
    "csrf": {
        "name": "跨站请求伪造 (CSRF)",
        "risk": "中危",
        "description": "攻击者可以诱导用户执行非预期的操作，如修改密码、转账等。",
        "fix": "1. 添加 Anti-CSRF Token\n2. 设置 SameSite=Strict/Lax Cookie\n3. 校验 Referer/Origin 头",
    },
    "race": {
        "name": "条件竞争 (Race Condition)",
        "risk": "中危",
        "description": "并发请求可能导致资源状态不一致，攻击者可利用此漏洞实现重复领取/越权操作。",
        "fix": "1. 使用数据库事务和锁机制\n2. 实现幂等性接口\n3. 使用分布式锁保证原子性",
    },
    "takeover": {
        "name": "子域名接管 (Subdomain Takeover)",
        "risk": "高危",
        "description": "已废弃的子域名指向外部服务（如云存储、CDN），攻击者可注册同名资源完全控制该域名。",
        "fix": "1. 移除废弃子域名的 DNS 记录\n2. 定期审计 CNAME 记录\n3. 使用托管 DNS 服务的所有权验证",
    },
    "info_leak": {
        "name": "敏感信息泄露",
        "risk": "中危",
        "description": "页面/接口中暴露了敏感信息（密钥、Token、内网地址等），可被攻击者利用扩大攻击面。",
        "fix": "1. 移除硬编码的凭据和密钥\n2. 使用环境变量管理配置\n3. 清理源代码中的调试信息",
    },
    "upload": {
        "name": "文件上传绕过",
        "risk": "高危",
        "description": "攻击者可以绕过上传限制上传恶意文件（WebShell），获取服务器控制权。",
        "fix": "1. 限制文件扩展名白名单\n2. 检查 Content-Type 和文件头\n3. 文件存储与执行路径分离",
    },
    "redirect": {
        "name": "开放重定向 (Open Redirect)",
        "risk": "低危",
        "description": "攻击者可以利用页面跳转功能将用户重定向到恶意站点，用于钓鱼攻击。",
        "fix": "1. 白名单限制可跳转的域名\n2. 对跳转 URL 进行校验\n3. 使用相对路径或固定跳转",
    },
}


async def bb_report(
    vuln_type: str = "",
    target: str = "",
    param: str = "",
    payload: str = "",
    impact: str = "",
    detail: str = "",
    poc: str = "",
) -> str:
    """
    漏洞报告生成 — 生成结构化的 SRC 格式漏洞报告

    Args:
        vuln_type: 漏洞类型 (xss/sqli/ssrf/ssti/cmdi/cors/idor/lfi/xxe/host_inject/csrf/race/takeover/info_leak/upload/redirect)
        target: 漏洞目标 URL
        param: 漏洞参数
        payload: 使用的 Payload
        impact: 漏洞影响描述
        detail: 漏洞详情
        poc: PoC 截图/请求

    Returns:
        格式化的 Markdown 漏洞报告
    """
    vuln_type = vuln_type.lower()
    vuln_info = VULN_DESCRIPTIONS.get(vuln_type, {
        "name": vuln_type,
        "risk": "待定",
        "description": "",
        "fix": "",
    })

    date_str = datetime.now().strftime("%Y-%m-%d")

    report = f"""# 漏洞报告

## 基本信息
- **漏洞类型**: {vuln_info['name']}
- **风险等级**: {vuln_info['risk']}
- **发现时间**: {date_str}
- **目标地址**: {target or '待补充'}

---

## 漏洞描述

{vuln_info['description']}

{detail}

---

## 复现步骤

### 1. 漏洞参数
- **参数位置**: {param or '待确认'}
- **Payload**: `{payload or '待补充'}`

### 2. 请求示例

```http
{poc or '工具自动填充区 - 如已执行扫描此处会自动填入 PoC 请求'}
```

### 3. 复现结果
{impact or '# 工具自动填充区 — 描述漏洞影响（如可读取的敏感数据量、受影响的用户数等）'}

---

## 影响范围

请结合实际业务填写受影响的范围（如用户数据、服务器、内部网络等）。

---

## 修复建议

{vuln_info['fix']}

---

## 参考资料

- [OWASP: {vuln_info['name']}](https://owasp.org/www-community/attacks/)
- [SRC 提交规范相关说明]

---
*报告由 Xuanmu Bug Bounty MCP 自动生成*
"""

    # 输出到结果
    result = []
    result.append(f"[*] 漏洞报告生成完成")
    result.append(f"[*] 类型: {vuln_info['name']} | 等级: {vuln_info['risk']}")
    result.append("")
    result.append(report)

    return "\n".join(result)
