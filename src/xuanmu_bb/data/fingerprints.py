"""Web 指纹库 — 多信号评分引擎"""

# ============================================================
# 每个指纹包含:
#   signals: 多组匹配信号，每组有权重
#   min_score: 判定为该技术的最低总分
#   version_extract: 可选，提取版本号的正则
#   negatives: 可选，反向排除信号
# ============================================================
FINGERPRINTS = [
    # ── 服务器 / 反向代理 ──
    {"name": "Nginx", "min_score": 60, "signals": [
        {"hdr": "Server", "pat": r"nginx", "w": 60},
    ], "negatives": [{"hdr": "Server", "pat": r"openresty", "w": 100}]},
    {"name": "OpenResty", "min_score": 60, "signals": [
        {"hdr": "Server", "pat": r"openresty", "w": 80},
    ]},
    {"name": "Apache", "min_score": 60, "signals": [
        {"hdr": "Server", "pat": r"Apache(?!.*nginx)", "w": 60},
    ], "negatives": [{"hdr": "Server", "pat": r"openresty|cloudflare", "w": 100}]},
    {"name": "IIS", "min_score": 60, "signals": [
        {"hdr": "Server", "pat": r"IIS", "w": 60},
    ]},
    {"name": "Tomcat", "min_score": 30, "signals": [
        {"body": r"Apache Tomcat", "w": 40},
        {"body": r"Tomcat", "w": 20},
    ]},

    # ── 编程语言 / 框架 ──
    {"name": "ASP.NET", "min_score": 60, "signals": [
        {"hdr": "X-AspNet-Version", "pat": r".+", "w": 80},
        {"hdr": "X-Powered-By", "pat": r"ASP\.NET", "w": 30},
    ], "version_extract": {"hdr": "X-AspNet-Version", "pat": r"([\d.]+)"}},
    {"name": "PHP", "min_score": 30, "signals": [
        {"hdr": "X-Powered-By", "pat": r"PHP", "w": 50},
        {"hdr": "Set-Cookie", "pat": r"PHPSESSID", "w": 40},
    ], "version_extract": {"hdr": "X-Powered-By", "pat": r"PHP/([\d.]+)"}},
    {"name": "Java", "min_score": 20, "signals": [
        {"hdr": "Set-Cookie", "pat": r"JSESSIONID", "w": 40},
        {"hdr": "X-Powered-By", "pat": r"Servlet", "w": 30},
    ]},
    {"name": "Python", "min_score": 20, "signals": [
        {"hdr": "Server", "pat": r"Werkzeug|gunicorn|uwsgi", "w": 40},
        {"hdr": "Set-Cookie", "pat": r"session", "w": 10},
    ]},
    {"name": "Node.js / Express", "min_score": 30, "signals": [
        {"hdr": "X-Powered-By", "pat": r"Express", "w": 50},
        {"body": r"Express", "w": 15},
    ]},

    # ── CMS ──
    {"name": "WordPress", "min_score": 40, "signals": [
        {"body": r'/wp-content/', "w": 40},
        {"body": r'/wp-includes/', "w": 30},
        {"body": r'wp-json', "w": 20},
        {"body": r'wp-admin', "w": 15},
        {"body": r'WordPress', "w": 15},
    ], "version_extract": {"body": "(?i)WordPress\\s+([\\d.]+)", "pat": "([\\d.]+)"}},
    {"name": "Drupal", "min_score": 30, "signals": [
        {"body": r'Drupal|drupal', "w": 30},
        {"body": r'Sites managed by Drupal', "w": 30},
        {"body": r'/sites/default/', "w": 20},
    ]},
    {"name": "Joomla", "min_score": 30, "signals": [
        {"body": r'/components/', "w": 20},
        {"body": r'/modules/', "w": 15},
        {"body": r'Joomla', "w": 20},
    ]},
    {"name": "Discuz!", "min_score": 30, "signals": [
        {"body": r'Discuz!', "w": 30},
        {"body": r'comsenz', "w": 30},
    ]},
    {"name": "Dedecms", "min_score": 30, "signals": [
        {"body": r'DedeCMS|dedecms', "w": 30},
        {"body": r'Power by DedeCms', "w": 30},
    ]},

    # ── 开发框架 ──
    {"name": "ThinkPHP", "min_score": 30, "signals": [
        {"body": r'ThinkPHP', "w": 30},
        {"body": r'thinkphp', "w": 15},
    ]},
    {"name": "Laravel", "min_score": 30, "signals": [
        {"body": r'Laravel', "w": 20},
        {"body": r'laravel', "w": 15},
        {"hdr": "Set-Cookie", "pat": r"laravel_session", "w": 30},
    ]},
    {"name": "Yii", "min_score": 20, "signals": [
        {"body": r'Yii', "w": 20},
        {"body": r'yiiframework', "w": 20},
    ]},
    {"name": "Spring Boot", "min_score": 30, "signals": [
        {"body": r'Whitelabel Error Page', "w": 40},
        {"body": r'actuator', "w": 20},
        {"body": r'spring', "w": 15},
        {"hdr": "Set-Cookie", "pat": r"JSESSIONID", "w": 15},
    ]},
    {"name": "Django", "min_score": 30, "signals": [
        {"body": r'csrfmiddlewaretoken', "w": 40},
        {"body": r'Django', "w": 25},
        {"hdr": "Set-Cookie", "pat": r"csrftoken", "w": 30},
    ]},
    {"name": "Flask", "min_score": 20, "signals": [
        {"body": r'Flask', "w": 15},
        {"hdr": "Set-Cookie", "pat": r"session", "w": 10},
    ]},
    {"name": "FastAPI", "min_score": 20, "signals": [
        {"body": r'FastAPI', "w": 20},
    ]},
    {"name": "Shiro", "min_score": 40, "signals": [
        {"hdr": "Set-Cookie", "pat": r"rememberMe", "w": 50},
    ]},

    # ── API / 文档 ──
    {"name": "Swagger UI", "min_score": 30, "signals": [
        {"body": r'swagger-ui', "w": 30},
        {"body": r'Swagger UI', "w": 30},
    ]},
    {"name": "Kubernetes", "min_score": 30, "signals": [
        {"body": r'Kubernetes|k8s|kube-system', "w": 30},
    ]},
    {"name": "Kubernetes API", "min_score": 50, "signals": [
        {"hdr": "Server", "pat": r"Kubernetes", "w": 80},
    ]},
]

# ============================================================
# WAF 签名（供 fingerprint.py 使用，与 data/waf.py 的 WAF_RULES 独立）
# ============================================================
WAF_SIGNATURES = [
    {"name": "Cloudflare",      "headers": {"Server": "cloudflare", "CF-RAY": r".*"},    "body": r"Cloudflare",       "bypass": "尝试直接访问源站 IP，或使用特殊 UA/Headers"},
    {"name": "Cloudfront",      "headers": {"Server": "CloudFront|Cloudfront|cloudfront"}, "body": r""},
    {"name": "Akamai",          "headers": {"Server": "AkamaiGHost"},                      "body": r"akamai"},
    {"name": "AWS WAF",         "headers": {},                                              "body": r"AWS WAF|awswaf|waf-"},
    {"name": "ModSecurity",     "headers": {},                                              "body": r"ModSecurity|This error was generated by Mod_Security", "bypass": "尝试 CRLF 注入、协议违规绕过"},
    {"name": "阿里云 WAF",       "headers": {},                                              "body": r"errors.aliyun.com|阿里云 Web 应用防火墙", "bypass": "尝试编码绕过、分块传输、HTTP 参数污染"},
    {"name": "腾讯云 WAF",       "headers": {},                                              "body": r"tencent.cloud.waf|waf.tencent", "bypass": "尝试大小写混淆、双重 URL 编码"},
    {"name": "百度云 WAF",       "headers": {},                                              "body": r"baidu.waf|百度云加速"},
    {"name": "360 主机卫士",     "headers": {},                                              "body": r"360wzws|360 Web Application Firewall"},
    {"name": "安全狗",           "headers": {},                                              "body": r"SafeDog|安全狗",    "bypass": "尝试换行绕过、注释混淆"},
    {"name": "D盾",             "headers": {},                                              "body": r"D\.D\.Waf|D盾"},
    {"name": "长亭 SafeLine",    "headers": {},                                              "body": r"SafeLine|chaitin",  "bypass": "尝试请求方法转换、参数变异"},
    {"name": "Naxsi",           "headers": {},                                              "body": r"naxsi|NAXSI"},
    {"name": "Comodo WAF",      "headers": {},                                              "body": r"COMODO"},
    {"name": "F5 BIG-IP",       "headers": {},                                              "body": r"BIG-IP|F5"},
    {"name": "Barracuda",       "headers": {},                                              "body": r"Barracuda"},
    {"name": "Sucuri",          "headers": {},                                              "body": r"Sucuri|cloudproxy"},
    {"name": "Wordfence",       "headers": {},                                              "body": r"Wordfence"},
]
