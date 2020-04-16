import unittest

from munch import Munch

from core.static.utils import StaticData
from tests.fixtures.protocols import IP_TCP_PROTOCOL, LAYER4_9898_PROTOCOL_INFO


class StaticDataTests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(StaticDataTests, self).__init__(*args, **kwargs)

    def test_ip_protocols_data_file_loads_successfully(self):
        ip_protocol_data = StaticData.load_ip_protocols_data()
        self.assertIsInstance(ip_protocol_data, Munch)

    def test_ip_protocols_data_contains_expected_data(self):
        # Check all keys are stringified integers
        for key in StaticData.load_ip_protocols_data().keys():
            self.assertIsInstance(int(key), int)
        ip_protocol_data = StaticData.load_ip_protocols_data()
        self.assertEqual(ip_protocol_data["6"], IP_TCP_PROTOCOL)

    def test_ip_protocols_data_returns_none_for_non_existing_key(self):
        ip_protocol_data = StaticData.load_ip_protocols_data()
        # Check all keys are stringified integers
        for key in ip_protocol_data.keys():
            self.assertIsInstance(int(key), int)

        self.assertIsNone(ip_protocol_data["non-existing-key"])

    def test_tcp_flags_data_loads_successfully(self):
        tcp_flags_data = StaticData.load_tcp_flag_data()
        self.assertIsInstance(tcp_flags_data, Munch)

    def test_tcp_flags_data_contains_expected_data(self):
        tcp_flags_data = StaticData.load_tcp_flag_data()
        self.assertEqual(len(tcp_flags_data.keys()), 7)
        self.assertEqual(tcp_flags_data["32"], "URG")

    def test_layer4_ports_data_loads_successfully(self):
        layer4_ports_data = StaticData.load_layer4_ports_data()
        self.assertIsInstance(layer4_ports_data, Munch)

    def test_layer4_ports_data_contains_expected_data(self):
        layer4_ports_data = StaticData.load_layer4_ports_data()
        for key in layer4_ports_data.keys():
            self.assertIsInstance(int(key), int)
        self.assertIsInstance(layer4_ports_data["9898"], list)
        self.assertIsInstance(layer4_ports_data["9898"][0], dict)
        self.assertEqual(layer4_ports_data["9898"], LAYER4_9898_PROTOCOL_INFO)
