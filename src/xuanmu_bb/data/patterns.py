"""正则模式数据 — 敏感信息 / 安全头"""

# ============================================================
# 敏感信息正则
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
# 安全头列表
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
