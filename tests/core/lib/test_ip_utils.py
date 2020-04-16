import unittest

from core.lib.ip_utils import IpAddrUtils
from tests.fixtures.ip_addresses import IPv6_ADDRESSES


class IpUtilsTests(unittest.TestCase):
    def test_ipv6_regex_validation(self):
        ip_utils = IpAddrUtils()
        for ip_addr in IPv6_ADDRESSES:
            self.assertTrue(ip_utils.is_valid_ip(ip_addr))

    def test_ipv4_regex_validation(self):
        ip_utils = IpAddrUtils()
        for ip_addr in IPv6_ADDRESSES:
            self.assertTrue(ip_utils.is_valid_ip(ip_addr))
