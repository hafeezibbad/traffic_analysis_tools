import unittest

from core.lib.mac_utils import MacAddressUtils
from tests.fixtures.mac_addresses import MAC_ADDRESSES


class MacUtilsTests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(MacUtilsTests, self).__init__(*args, **kwargs)
        self.mac_utils = MacAddressUtils()

    def test_mac_regex_validation(self):
        for mac_addr in MAC_ADDRESSES:
            self.assertTrue(self.mac_utils.is_valid_mac(mac_addr))

    def test_int2mac_returns_valid_mac(self):
        for mac_addr in MAC_ADDRESSES:
            self.assertIsInstance(self.mac_utils.mac_to_int(mac_addr), int)

    def test_mac_to_int_to_mac_works_as_expected(self):
        for mac_addr in MAC_ADDRESSES:
            integer_mac = self.mac_utils.mac_to_int(mac_addr)
            self.assertEqual(mac_addr, self.mac_utils.int_to_mac(integer_mac))

    def test_convert_hexadecimal_mac_to_readable_mac_works_as_expected(self):
        for mac_addr in MAC_ADDRESSES:
            byte_mac = self.mac_utils.convert_string_mac_to_byte_array(mac_addr)
            self.assertIsInstance(byte_mac, bytearray)
            self.assertEqual(mac_addr, self.mac_utils.convert_hexadecimal_mac_to_readable_mac(byte_mac))

    def test_convert_hexadecimal_mac_to_readable_mac_as_expected(self):
        for mac_addr in MAC_ADDRESSES:
            byte_mac = self.mac_utils.convert_string_mac_to_byte_array(mac_addr)
            self.assertIsInstance(byte_mac, bytearray)
            self.assertEqual(mac_addr, self.mac_utils.convert_hexadecimal_mac_to_readable_mac(byte_mac))

    def test_get_mac_address_to_byte_str_returns_none_given_mac_is_invalid(self):
        self.assertIsNone(self.mac_utils.convert_string_mac_to_byte_array(mac_address=None))            # MAC is None
        self.assertIsNone(self.mac_utils.convert_string_mac_to_byte_array(mac_address=''))              # MAC is empty
        self.assertIsNone(self.mac_utils.convert_string_mac_to_byte_array(mac_address='invalidmac'))    # MAC is invalid
