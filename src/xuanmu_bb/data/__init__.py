"""内置数据 — 向后兼容的统一入口

所有数据已拆分至子模块:
  - data.payloads  : SQLI/XSS/SSTI/CMDI/SSRF/LFI/REDIRECT payloads
  - data.dicts     : SUBDOMAIN_DICT, DIR_DICT, COMMON_PORTS, TOP_PORTS, WEAK_*
  - data.fingerprints : FINGERPRINTS, WAF_SIGNATURES
  - data.patterns  : SECRET_PATTERNS, SECURITY_HEADERS
  - data.waf       : WAF 检测引擎

本文件保持向后兼容：所有原有名称仍然可从此处 import。
"""

from xuanmu_bb.data.payloads import (
    SQLI_PAYLOADS, XSS_PAYLOADS, SSTI_PAYLOADS,
    CMDI_PAYLOADS, SSRF_PAYLOADS, LFI_PAYLOADS, REDIRECT_PAYLOADS,
)
from xuanmu_bb.data.dicts import (
    SUBDOMAIN_DICT, DIR_DICT, COMMON_PORTS, TOP_PORTS,
    WEAK_PASSWORDS, WEAK_USERNAMES,
)
from xuanmu_bb.data.fingerprints import (
    FINGERPRINTS, WAF_SIGNATURES,
)
from xuanmu_bb.data.patterns import (
    SECRET_PATTERNS, SECURITY_HEADERS,
)
