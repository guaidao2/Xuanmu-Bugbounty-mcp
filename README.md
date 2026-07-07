# Xuanmu-BugBounty-mcp

> **玄幕安全团队 · guaidao2 开发**
>
> 独立自包含的 SRC 挖洞专用 MCP 工具包 — 零外部扫描器依赖，即装即用

---

## 快速安装

```bash
git clone https://github.com/guaidao2/Xuanmu-Bugbounty-mcp.git
cd Xuanmu-BugBounty-mcp
pip install -e . -i https://pypi.tuna.tsinghua.edu.cn/simple

# 启动
xuanmu-bb
# 或: python "绝对路径/src/xuanmu_bb/server.py"
```

---

## MCP 配置

```json
{
  "mcpServers": {
    "Xuanmu-BugBounty-mcp": {
      "command": "xuanmu-bb"
    }
  }
}
```

---

## 核心特性

### 结构化输出

所有漏洞检测工具返回统一的 JSON 格式，LLM 可直接解析：

```json
{
  "tool": "bb_sqli",
  "target": "https://example.com",
  "status": "confirmed",
  "summary": "发现 3 个可疑点（2个CRITICAL, 1个HIGH），其中 2 个已确认",
  "findings": [{
    "param": "id", "payload": "' AND SLEEP(3) --",
    "type": "time_based", "severity": "CRITICAL",
    "evidence": "时间盲注: 响应延迟 3.2s",
    "verified": true,
    "verified_by": "二次确认: sleep(5) 延迟 5.1s"
  }],
  "waf": {"detected": true, "name": "Cloudflare"},
  "metadata": {"duration_ms": 8234, "requests_sent": 45}
}
```

### 检测结果二次确认

| 漏洞类型 | 首次检测 | 二次确认方式 |
|---------|---------|-------------|
| SQLi 时间盲注 | SLEEP(3) 延迟 | 重试 SLEEP(5) 验证 |
| SQLi 布尔盲注 | 1=1 vs 1=2 差异 | 换 2=2 vs 2=1 验证 |
| XSS | payload 未编码反射 | 不同向量 (<img> -> <svg>) 交叉验证 |
| SSTI | 7\*7 -> 49 | 验证 8\*8 -> 64 |
| CMDI | ping -c 3 延迟 | 重试 ping -c 5 |
| SSRF/LFI | 响应含系统文件 | 自动确认；大小变化则换地址重试 |

确认后的 finding 标记 `verified: true`，severity 升为 CRITICAL。

### 自定义 Payload

所有漏洞检测工具支持 `custom_payloads` 参数，与内置 Payload 合并执行：

```bash
bb_sqli url="..." custom_payloads="' OR 1=1 -- ,1' AND SLEEP(10) -- "
bb_xss  url="..." custom_payloads="<script>alert(document.cookie)</script>,<img src=x onerror=alert(1)>"
```

### 增强指纹识别

融合 **Wappalyzer + EHole + FingerprintHub** 三大项目的检测思路：

| 检测源 | 数量 | 方法 |
|-------|------|------|
| FingerprintHub 全量 | **2,224 条** | 关键词AND + 33 favicon哈希 + 评分 |
| 增强指纹库 | 79 条 | 多信号评分 + 关键词AND + 隐含推导 |
| Wappalyzer | 运行时 | 库检测 |
| Favicon 哈希 | 运行时 | MMH3 32-bit 计算 (Shodan/EHole 兼容) |
| Meta Generator | 运行时 | HTML meta 标签提取 CMS+版本 |

**覆盖 27 个技术分类**：CMS、OA/办公、ERP/财务、框架/语言、Web服务器、CDN/代理、WAF/安全、数据库、网络设备、监控/日志、邮件系统、VPN/远程、堡垒机、DevOps、视频监控、NAS/IoT、云服务等。

**隐含技术推导**：WordPress -> PHP + MySQL、Django -> Python、Spring Boot -> Java、Element UI -> Vue.js ...

输出按技术分类分组，附带 WAF 检测和后续测试建议。

```bash
bb_fingerprint url="https://example.com"
```

---

## 全部 39 个工具

> 以下工具凡涉及 HTTP 请求的，均支持通用认证参数：`auth_token`（Bearer Token）、`cookie`、`proxy`、`timeout`。
> 漏洞检测类工具额外支持：`waf_mode`、`method`（GET/POST）、`body`、`custom_payloads`。

### 侦察模块

| 工具 | 功能 | 特有参数 |
|------|------|---------|
| `bb_ping` | 存活探测 — TCP + HTTP 双重检测 | target |
| `bb_port_scan` | 端口扫描 — Top100/自定义范围 | target, ports, concurrent |
| `bb_subdomain` | 子域名枚举 — DNS 批量解析 | domain, wordlist, concurrent |
| `bb_fingerprint` | **增强指纹识别** — 2300+指纹/27分类/favicon哈希 | url |
| `bb_dir_scan` | 目录爆破 — 内置 150+ 敏感路径 | url, wordlist, status_filter, concurrent |

### 漏洞检测模块

| 工具 | 功能 | 特有参数 |
|------|------|---------|
| `bb_sqli` | SQL 注入 — 报错/布尔/时间盲注 + 二次确认 | url, params, custom_payloads |
| `bb_nosqli` | NoSQL 注入 — MongoDB \$ne/\$gt/\$regex | url, params |
| `bb_xss` | XSS 检测 — 反射型/多上下文 + 交叉验证 | url, params, custom_payloads |
| `bb_ssti` | SSTI 模板注入 — 多引擎 + 数值确认 | url, params, custom_payloads |
| `bb_cmdi` | 命令注入 — 时间盲注+输出回显 + 确认 | url, params, custom_payloads |
| `bb_ssrf` | SSRF 检测 — 内网/云元数据/OOB + 确认 | url, params, custom_payloads |
| `bb_cors` | CORS 跨域 — 12 种 Origin 测试 | url |
| `bb_open_redirect` | 开放重定向 — 参数扫描+跳转测试 | url, params |
| `bb_file_upload` | 文件上传绕过 — 多扩展名/MIME/截断 | url |
| `bb_csrf` | CSRF 检测 — Token/SameSite/Referer 分析 | url |
| `bb_xxe` | XXE 检测 — 经典/Blind/SVG/XInclude | url, body, content_type |
| `bb_lfi` | 路径遍历 — ../遍历/PHP filter + 确认 | url, params, custom_payloads |
| `bb_host_inject` | Host 头注入 — 9 种攻击场景 | url |
| `bb_takeover` | 子域名接管 — CNAME+50+云服务匹配 | domain |
| `bb_race` | 条件竞争 — 并发请求+响应差异分析 | url, method, data, concurrent |

### 认证安全模块

| 工具 | 功能 | 特有参数 |
|------|------|---------|
| `bb_jwt_decode` | JWT 解码 — 解析 Header/Payload | token |
| `bb_jwt_analyze` | JWT 安全分析 — 漏洞检测+攻击建议 | token |
| `bb_jwt_crack` | JWT 密钥爆破 — HMAC 字典攻击 | token, wordlist |
| `bb_jwt_attack` | JWT 攻击 — None/KID注入/算法混淆 | token, mode, payload_override, public_key |
| `bb_graphql` | GraphQL 扫描 — Introspection/批量/递归 | url |

### 信息提取模块

| 工具 | 功能 | 特有参数 |
|------|------|---------|
| `bb_extract` | URL/Endpoint 提取 — HTML+JS分析 | url, depth |
| `bb_secrets` | 敏感信息检测 — 20 种正则模式 | url, check_js |
| `bb_headers` | 安全头审计 — 8 项评分+修复建议 | url |
| `bb_param_discover` | 参数自动发现 — 表单/查询/JSON/JS | url, depth |
| `bb_js_analyze` | JS 深度分析 — API路由/Sourcemap/硬编码/WebSocket | url |

### 工具模块

| 工具 | 功能 | 特有参数 |
|------|------|---------|
| `bb_send` | 手工 HTTP 发包 — 自定义方法/头/Body | url, method, headers, body, content_type, follow_redirects |
| `bb_payload` | Payload 工厂 — 9 类漏洞 x 6 种编码 | vuln_type, encode, count |
| `bb_oob` | OOB 外带辅助 — 回调标识/Payload 建议 | mode, callback_url |
| `bb_idor` | IDOR 越权检测 — 双 Token 对比 + 序号枚举 | url, token_owner, token_attacker, param, method |
| `bb_cloud_check` | 云服务安全 — S3/元数据/云配置泄露 | url |
| `bb_waf_check` | WAF 指纹识别 — 14 种 WAF + 绕过建议 | url |
| `bb_session` | 多步骤流程 — Session保持 + 请求链 | steps (JSON) |
| `bb_report` | 漏洞报告生成 — SRC 格式 Markdown | vuln_type, target, param, payload, impact, detail, poc |

### 通用参数说明

| 参数 | 适用工具 | 说明 |
|------|---------|------|
| `auth_token` | 所有 HTTP 工具 | Bearer Token，自动添加 `Authorization: Bearer xxx` 头 |
| `cookie` | 所有 HTTP 工具 | Cookie 字符串，自动添加 `Cookie: xxx` 头 |
| `proxy` | 所有 HTTP 工具 | 代理地址，如 `http://127.0.0.1:8080` |
| `timeout` | 所有 HTTP 工具 | 请求超时秒数（默认 15） |
| `waf_mode` | 漏洞检测 | `off` / `safe`（降速+UA轮换）/ `aggressive`（尝试绕过） |
| `method` | 漏洞检测 | `GET` 或 `POST`，默认 GET |
| `body` | 漏洞检测 | POST 请求体，如 `username=admin&password=test` |
| `custom_payloads` | sqli/xss/ssti/cmdi/ssrf/lfi | 逗号分隔的自定义 Payload，与内置 Payload 合并执行 |
| `request_delay` | 漏洞检测+dir_scan | 请求间隔秒数，检测到 WAF 后自动升为 3s |

---

## 使用示例

### 信息收集 -> 漏洞检测 全流程

```bash
# 1. 指纹识别（识别技术栈 + WAF + 分类）
bb_fingerprint  url="https://target.com"

# 2. 目录扫描
bb_dir_scan     url="https://target.com"

# 3. 参数发现
bb_param_discover url="https://target.com/api"

# 4. 漏洞检测（使用发现的参数 + 自定义 payload）
bb_sqli         url="https://target.com/page?id=1" params="id" \
                custom_payloads="' OR 1=1 -- ,' AND SLEEP(5) -- "

bb_xss          url="https://target.com/search?q=test" params="q" \
                custom_payloads="<script>alert(1)</script>,<img src=x onerror=alert(1)>"

bb_ssti         url="https://target.com/welcome?name=test" params="name"
bb_cmdi         url="https://target.com/ping?host=127.0.0.1" params="host"
bb_ssrf         url="https://target.com/fetch?url=http://example.com" params="url"
bb_lfi          url="https://target.com/file?name=test.txt" params="name"
bb_cors         url="https://api.target.com/data"
bb_open_redirect url="https://target.com/redirect?url=https://example.com"
bb_xxe          url="https://target.com/xml/parse"

# 5. 认证测试
bb_jwt_analyze  token="eyJhbGciOiJIUzI1NiIs..."
bb_jwt_attack   token="..." mode="none"
bb_graphql      url="https://target.com/graphql"

# 6. 多步骤业务流
bb_session      steps='[
  {"method":"POST","url":"https://target.com/login","body":"user=admin&pass=test"},
  {"method":"GET","url":"https://target.com/api/profile"}
]'

# 7. 生成报告
bb_report       vuln_type="sqli" target="https://target.com/page?id=1" \
                payload="' OR 1=1 -- " impact="可获取数据库所有数据"
```

### 带认证扫描

```bash
# Bearer Token
bb_sqli url="https://target.com/api/search" params="q" auth_token="eyJ..."

# Session Cookie
bb_xss url="https://target.com/search" params="q" cookie="JSESSIONID=ABCD1234"
```

### WAF 防护扫描

```bash
# 先检测 WAF
bb_waf_check url="https://target.com"

# 带 WAF 防护扫描（自动降速 + UA轮换）
bb_sqli url="https://target.com/page?id=1" waf_mode="safe" request_delay="3"
```

---

## 项目结构

```
src/xuanmu_bb/
├── server.py              # MCP 入口（39 工具，注册表模式）
├── client.py              # HTTP 客户端（代理/Cookie/UA轮换/反封策略）
├── utils.py               # 公共工具 + ResultBuilder 结构化输出
├── data/
│   ├── payloads.py           # SQLi/XSS/SSTI/CMDI/SSRF/LFI Payload
│   ├── dicts.py              # 子域/目录字典 + 端口映射 + 弱口令
│   ├── fingerprints.py       # Web 指纹库 + WAF 签名
│   ├── fingerprints_enhanced.py  # 增强指纹库（79条，27分类）
│   ├── fingerprints_hub.py   # FingerprintHub 全量（2,224条，365KB）
│   ├── patterns.py           # 敏感信息正则 + 安全头列表
│   └── waf.py                # WAF 检测引擎
├── recon/                 # 侦察模块（5 工具）
├── vuln/                  # 漏洞检测模块（15 工具，均支持二次确认）
├── auth/                  # 认证安全模块（5 工具）
├── extract/               # 信息提取模块（5 工具）
└── tools/                 # 工具模块（9 工具 + fingerprint_importer）
```

---

## 技术特点

- **完全自包含** — 不依赖 nmap/nuclei/burp 等外部工具，纯 Python 实现
- **结构化 JSON 输出** — 所有漏洞检测返回统一格式，LLM 可直接解析联动
- **检测二次确认** — SQLi/XSS/SSTI/CMDI/SSRF/LFI 自动验证减少误报
- **2300+ 指纹库** — 融合 FingerprintHub + Wappalyzer + EHole，覆盖 27 个技术分类
- **Favicon 哈希** — MMH3 32-bit 计算，兼容 Shodan/EHole 指纹匹配
- **自定义 Payload** — 所有漏洞工具支持用户注入自定义 Payload
- **反封策略** — User-Agent 轮换 / 请求间隔控制 / 代理支持 / WAF 熔断
- **注册表模式** — server.py 新增工具仅需一行元组，无需重复样板代码
- **16 个单元测试** — 覆盖 utils、payloads、dicts 核心模块

---

## 许可证

本项目仅供合法的安全测试与漏洞挖掘使用。使用者需遵守相关法律法规。

---

**Xuanmu-BugBounty-mcp** (c) 2026 玄幕安全团队 · guaidao2
