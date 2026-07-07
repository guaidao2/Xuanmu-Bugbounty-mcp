"""Xuanmu Bug Bounty MCP 测试"""

import pytest


class TestUtils:
    """utils.py 工具函数测试"""

    def test_normalize_url_adds_https(self):
        from xuanmu_bb.utils import normalize_url
        assert normalize_url("example.com") == "https://example.com"
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_normalize_url_preserves_scheme(self):
        from xuanmu_bb.utils import normalize_url
        assert normalize_url("http://example.com/path") == "http://example.com/path"

    def test_parse_ports_single(self):
        from xuanmu_bb.utils import parse_ports
        assert parse_ports("80") == [80]

    def test_parse_ports_range(self):
        from xuanmu_bb.utils import parse_ports
        assert parse_ports("80-82") == [80, 81, 82]

    def test_parse_ports_mixed(self):
        from xuanmu_bb.utils import parse_ports
        assert parse_ports("80,443,8080-8081") == [80, 443, 8080, 8081]

    def test_extract_params_from_url_with_query(self):
        from xuanmu_bb.utils import extract_params_from_url
        params = extract_params_from_url("https://example.com?q=test&page=1")
        assert "q" in params
        assert "page" in params

    def test_extract_params_from_url_with_string(self):
        from xuanmu_bb.utils import extract_params_from_url
        params = extract_params_from_url("https://example.com", "a,b,c")
        assert params == ["a", "b", "c"]

    def test_build_url_with_param(self):
        from xuanmu_bb.utils import build_url_with_param
        result = build_url_with_param("https://example.com?q=test", "q", "injected")
        assert "q=injected" in result

    def test_is_valid_domain(self):
        from xuanmu_bb.utils import is_valid_domain
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.co.uk")
        assert not is_valid_domain("not a domain")

    def test_is_valid_ip(self):
        from xuanmu_bb.utils import is_valid_ip
        assert is_valid_ip("127.0.0.1")
        assert not is_valid_ip("999.999.999.999")


class TestPayloads:
    """data/payloads.py 数据完整性测试"""

    def test_sqli_payloads_not_empty(self):
        from xuanmu_bb.data import SQLI_PAYLOADS
        assert len(SQLI_PAYLOADS) > 10
        assert all("payload" in p and "type" in p for p in SQLI_PAYLOADS)

    def test_xss_payloads_not_empty(self):
        from xuanmu_bb.data import XSS_PAYLOADS
        assert len(XSS_PAYLOADS) > 5

    def test_all_payload_types_present(self):
        from xuanmu_bb.data import (SQLI_PAYLOADS, XSS_PAYLOADS, SSTI_PAYLOADS,
                                     CMDI_PAYLOADS, SSRF_PAYLOADS, LFI_PAYLOADS)
        assert len(SQLI_PAYLOADS) > 0
        assert len(XSS_PAYLOADS) > 0
        assert len(SSTI_PAYLOADS) > 0
        assert len(CMDI_PAYLOADS) > 0
        assert len(SSRF_PAYLOADS) > 0
        assert len(LFI_PAYLOADS) > 0


class TestDicts:
    """data/dicts.py 字典数据测试"""

    def test_common_ports_has_expected(self):
        from xuanmu_bb.data import COMMON_PORTS
        assert COMMON_PORTS.get(80) == "HTTP"
        assert COMMON_PORTS.get(443) == "HTTPS"
        assert COMMON_PORTS.get(3306) == "MySQL"

    def test_top_ports_not_empty(self):
        from xuanmu_bb.data import TOP_PORTS
        assert len(TOP_PORTS) > 50
        assert 80 in TOP_PORTS
        assert 443 in TOP_PORTS

    def test_subdomain_dict_not_empty(self):
        from xuanmu_bb.data import SUBDOMAIN_DICT
        assert len(SUBDOMAIN_DICT) > 100
        assert "www" in SUBDOMAIN_DICT
