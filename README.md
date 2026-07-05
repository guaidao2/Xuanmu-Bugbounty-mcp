# 🎯 Xuanmu-BugBounty-mcp

> **玄幕安全团队 · guaidao2 开发**
>
> 独立自包含的 SRC 挖洞专用 MCP 工具包 — 零外部依赖，即装即用

---

## 📦 快速安装

```bash
# 1. 克隆仓库
git clone https://github.com/guaidao2/Xuanmu-Bugbounty-mcp.git
cd Xuanmu-BugBounty-mcp

# 2. 安装依赖（使用清华源）
pip install -e . -i https://pypi.tuna.tsinghua.edu.cn/simple

# 或使用 requirements.txt
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 3. 启动 MCP 服务器（stdio 模式）
# 方式一：直接启动（推荐）
xuanmu-bb

# 方式二：使用 python + 脚本绝对路径启动
python "绝对路径/src/xuanmu_bb/server.py"
```

---

## 🔌 MCP 配置

在支持 MCP 的客户端（如 Claude Desktop、Cursor、Windsurf 等）中配置：

**方式一：使用 `xuanmu-bb` 命令（推荐）**

```json
{
  "mcpServers": {
    "Xuanmu-BugBounty-mcp": {
      "command": "xuanmu-bb",
      "args": []
    }
  }
}
```

**方式二：使用 python + 脚本文件绝对路径调用**

```json
{
  "mcpServers": {
    "Xuanmu-BugBounty-mcp": {
      "command": "python",
      "args": ["你的项目绝对路径/src/xuanmu_bb/server.py"]
    }
  }
}
```

> 💡 将 `你的项目绝对路径` 替换为你实际存放项目的完整路径
> Windows 示例：`"D:\\Projects\\Xuanmu-BugBounty-mcp\\src\\xuanmu_bb\\server.py"`

---

## 🔐 认证方式（两种都支持）

目标需要登录？所有 HTTP 工具都支持两种认证：

| 方式 | 参数 | 适用场景 |
|------|------|---------|
| Bearer Token | `auth_token="xxx"` | JWT / OAuth2 令牌登录的系统 |
| Session Cookie | `cookie="SESSION=xxx"` | 表单登录 / PHP/Java Session 的系统 |

```bash
# Bearer Token（API 认证）
bb_sqli url="https://target.com/api/search" params="q" auth_token="eyJhbGciOiJIUzI1NiIs..."

# Session Cookie（Web 认证）
bb_xss url="https://target.com/search" params="q" cookie="JSESSIONID=ABCD1234"

# 先探测认证状态
bb_param_discover url="https://target.com"
# 输出会标注: [AUTH: required] HTTP 401 或 [AUTH: none] HTTP 200
```

---

## 🧰 全部 39 个工具

### 🔍 侦察模块 (Reconnaissance)

| 工具 | 功能 | 参数 |
|------|------|------|
| `bb_ping` | 存活探测 — TCP + HTTP 双重检测 | target, timeout, proxy |
| `bb_port_scan` | 端口扫描 — Top100/自定义范围 | target, ports, timeout, concurrent |
| `bb_subdomain` | 子域名枚举 — DNS 批量解析 | domain, wordlist, concurrent |
| `bb_fingerprint` | Web 指纹识别 — 技术栈/CMS/WAF | url, proxy, cookie, auth_token |
| `bb_dir_scan` | 目录爆破 — 内置 150+ 敏感路径 | url, wordlist, status_filter, concurrent, cookie, auth_token |

### 🔥 漏洞检测模块 (Vulnerability Detection)

| 工具 | 功能 | 参数 |
|------|------|------|
| `bb_sqli` | SQL 注入 — 报错/布尔/时间盲注 | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_nosqli` | **NoSQL 注入** — MongoDB $ne/$gt/$regex | url, params, method, body, auth_token, cookie |
| `bb_xss` | XSS 检测 — 反射型/多种上下文 | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_ssti` | SSTI 模板注入 — 多引擎检测 | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_cmdi` | 命令注入 — 时间盲注+输出回显 | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_ssrf` | SSRF 检测 — 内网/云元数据/OOB | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_cors` | CORS 跨域 — 12 种 Origin 测试 | url, auth_token, cookie |
| `bb_open_redirect` | 开放重定向 — 参数扫描+跳转测试 | url, params, auth_token, cookie |
| `bb_file_upload` | 文件上传绕过 — 实际上传+验证可访问 | url, auth_token, cookie |
| `bb_csrf` | CSRF 检测 — Token/SameSite/Referer | url, auth_token, cookie |
| `bb_xxe` | XXE 检测 — 经典/Blind/SVG/XInclude | url, body, auth_token, cookie |
| `bb_lfi` | 路径遍历 — ../遍历/PHP filter | url, params, method, body, auth_token, cookie, waf_mode |
| `bb_host_inject` | Host 头注入 — 9 种攻击场景 | url, auth_token, cookie |
| `bb_takeover` | 子域名接管 — CNAME+50+云服务匹配 | domain, auth_token |
| `bb_race` | 条件竞争 — 并发请求+响应差异分析 | url, method, data/body, concurrent, auth_token, cookie |

### 🔐 认证安全模块 (Authentication Security)

| 工具 | 功能 | 参数 |
|------|------|------|
| `bb_jwt_decode` | JWT 解码 — 解析 Header/Payload | token |
| `bb_jwt_analyze` | JWT 安全分析 — 漏洞检测+攻击建议 | token |
| `bb_jwt_crack` | JWT 密钥爆破 — HMAC 字典攻击 | token, wordlist |
| `bb_jwt_attack` | JWT 攻击 — None/KID注入/算法混淆 | token, mode, payload_override, public_key |
| `bb_graphql` | GraphQL 扫描 — Introspection/批量/递归 | url, auth_token, cookie |

### 📋 信息提取模块 (Information Extraction)

| 工具 | 功能 | 参数 |
|------|------|------|
| `bb_extract` | URL/Endpoint 提取 — HTML+JS分析 | url, depth, auth_token, cookie |
| `bb_secrets` | 敏感信息检测 — 20 种正则模式 | url, auth_token, cookie, check_js |
| `bb_headers` | 安全头审计 — 8 项评分+修复建议 | url, auth_token, cookie |
| `bb_param_discover` | **参数自动发现** — 提取表单/查询/JSON/JS | url, depth, auth_token, cookie |
| `bb_js_analyze` | **JS 深度分析** — API路由/Sourcemap/硬编码/SPA/WebSocket | url, auth_token, cookie |

### 🧰 工具模块 (Utilities)

| 工具 | 功能 | 参数 |
|------|------|------|
| `bb_send` | 手工 HTTP 发包 — 自定义方法/头/Body | url, method, headers, body, auth_token, cookie |
| `bb_payload` | Payload 工厂 — 9 类漏洞×6 种编码 | vuln_type, encode, count |
| `bb_oob` | **OOB 外带辅助** — 生成回调标识/Payload | mode, callback_url |
| `bb_idor` | **IDOR 越权检测** — 双 Token 对比 + 序号枚举 | url, token_owner, token_attacker, method, param |
| `bb_cloud_check` | **云服务安全** — S3/元数据/云配置泄露 | url, auth_token, cookie |
| `bb_waf_check` | **WAF 指纹识别** — 14 种 WAF + 绕过建议 | url, auth_token, cookie |
| `bb_session` | **多步骤流程** — Session保持 + 请求链 | steps (JSON), proxy |
| `bb_report` | 漏洞报告生成 — SRC 格式 Markdown | vuln_type, target, param, payload, impact |

---

## 🚀 使用示例

```bash
# 侦察一个目标
bb_ping         target="example.com"
bb_port_scan    target="example.com" ports="80,443,8080-8090"
bb_subdomain    domain="example.com"
bb_fingerprint  url="https://example.com"
bb_dir_scan     url="https://example.com"

# 漏洞检测
bb_sqli         url="https://example.com/page?id=1" params="id"
bb_xss          url="https://example.com/search?q=test" params="q"
bb_ssti         url="https://example.com/welcome?name=test" params="name"
bb_cmdi         url="https://example.com/ping?host=127.0.0.1" params="host"
bb_ssrf         url="https://example.com/fetch?url=http://example.com" params="url"
bb_cors         url="https://api.example.com/data"
bb_open_redirect url="https://example.com/redirect?url=https://example.com"
bb_csrf         url="https://example.com/change_password"
bb_xxe          url="https://example.com/xml/parse"
bb_lfi          url="https://example.com/file?name=test.txt" params="name"
bb_host_inject  url="https://example.com/reset"
bb_takeover     domain="sub.example.com"
bb_race         url="https://example.com/api/coupon/claim" method="POST"

# JWT 工具
bb_jwt_decode   token="eyJhbGciOiJIUzI1NiIs..."
bb_jwt_analyze  token="eyJhbGciOiJIUzI1NiIs..."
bb_jwt_crack    token="eyJhbGciOiJIUzI1NiIs..."
bb_jwt_attack   token="eyJhbGciOiJIUzI1NiIs..." mode="none"

# GraphQL
bb_graphql      url="https://example.com/graphql"

# 信息提取
bb_extract      url="https://example.com" depth=2
bb_secrets      url="https://example.com" check_js=true
bb_headers      url="https://example.com"

# POST body 注入（新增）
bb_sqli         url="https://target.com/api/login" method="POST" body="username=admin&password=test" params="username"
bb_xss          url="https://target.com/api/feedback" method="POST" body="message=test" params="message"
bb_cmdi         url="https://target.com/api/ping" method="POST" body="host=127.0.0.1" params="host"
bb_xxe          url="https://target.com/xml/parse" body="<?xml version='1.0'?><root>test</root>"
bb_lfi          url="https://target.com/api/read" method="POST" body="file=../../../../etc/passwd" params="file"
bb_ssti         url="https://target.com/welcome" method="POST" body="name={{7*7}}" params="name"

# 工具
bb_payload      vuln_type="xss" encode="all" count=20
bb_send         url="https://example.com/api/login" method="POST" headers='{"Content-Type": "application/json"}' body='{"user":"admin","pass":"123"}'
bb_report       vuln_type="sqli" target="https://example.com/page?id=1" payload="\' OR 1=1 -- "
bb_send         url="https://example.com/api/login" method="POST" headers='{"Content-Type": "application/json"}' body='{"user":"admin","pass":"123"}'
bb_report       vuln_type="sqli" target="https://example.com/page?id=1" payload="' OR 1=1 -- "

# JS 深度分析
bb_js_analyze   url="https://example.com" auth_token="..."

# WAF 检测
bb_waf_check    url="https://example.com"

# IDOR 越权检测
bb_idor         url="https://api.example.com/users/1234" \
                token_owner="eyJ...owner_token..." \
                token_attacker="eyJ...attacker_token..."

# 多步骤流程
bb_session      steps='[
  {"method":"POST","url":"https://target.com/login","body":"user=admin&pass=test"},
  {"method":"GET","url":"https://target.com/api/profile"}
]'

# 云服务检测
bb_cloud_check  url="https://example.com"

# 参数自动发现 + NoSQL 注入
bb_param_discover url="https://example.com/api"
bb_nosqli       url="https://example.com/api/user?id=1"
```

---

## 🛡️ WAF 防护引擎

支持 WAF 检测的扫描工具（sqli/xss/ssti/cmdi/ssrf/lfi/dir_scan）自动集成：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `waf_mode` | `safe` | `off`（不管）/ `safe`（降速+轮换UA）/ `aggressive`（尝试绕过） |
| `max_retries_on_block` | `3` | 被拦截后重试次数，超限自动熔断 |
| `request_delay` | `auto` | `auto`=检测到WAF后从0.5s升到3s，也可手动指定秒数 |

**工作流程:**
```
1. 预检 — 发无害请求检测 WAF 指纹
2. 发现 WAF → 自动降速 + 轮换 UA + 提示绕过建议
3. 扫描中 — 实时检测拦截页面 (403/503/验证页)
4. 熔断 — 连续 N 次被拦截 → 自动中断 → 输出熔断报告
```

先检测 WAF：
```bash
bb_waf_check url="https://target.com"
```

带 WAF 防护扫描：
```bash
bb_sqli url="https://target.com/page?id=1" waf_mode="safe" request_delay="3"
```

## 🏗️ 项目结构

```
src/xuanmu_bb/
├── server.py              # MCP 入口（38 个工具注册）
├── client.py              # HTTP 客户端（代理/Cookie/UA轮换/反封策略）
├── utils.py               # 公共工具函数
├── data/                  # 内置数据（Payload 字典/指纹/WAF库/正则模式）
├── recon/                 # 侦察模块（5 工具）
├── vuln/                  # 漏洞检测模块（15 工具）
├── auth/                  # 认证安全模块（5 工具）
├── extract/               # 信息提取模块（5 工具）
└── tools/                 # 工具模块（9 工具）
```

---

## 🧪 技术特点

- **完全自包含** — 不依赖 nmap/nuclei/burp 等外部工具，纯 Python 实现
- **零外部扫描器依赖** — 不依赖 yakit/tscanplus/nuclei，独立运行
- **内置丰富数据** — 200+ 子域字典 / 150+ 目录字典 / 1000+ 端口服务映射 / 500+ Payload
- **反封策略** — User-Agent 轮换 / 请求间隔控制 / 代理支持
- **清华源** — 默认使用 `pypi.tuna.tsinghua.edu.cn` 加速安装
- **覆盖 SRC 全流程** — 信息收集 → 漏洞检测 → 利用验证 → 报告生成

---

## 📝 许可证

本项目仅供合法的安全测试与漏洞挖掘使用。使用者需遵守相关法律法规。

---

**Xuanmu-BugBounty-mcp** © 2026 玄幕安全团队 · guaidao2
