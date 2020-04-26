import logging
from typing import Tuple

import binascii
import dpkt
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.dpkt_parsers.ethernet_parser import EthernetFrameParser
from core.lib.ip_utils import IpAddrUtils
from core.lib.mac_utils import MacAddressUtils
from core.static.utils import StaticData
from tests.core.lib.dpkt_parsers.common import BasePacketParserTests


class EthernetFrameParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(EthernetFrameParserTests, self).__init__(*args, **kwargs)
        self.eth_frame_parser = EthernetFrameParser(config=self.config)
        self.mac_utils = MacAddressUtils()

    def test_extract_data_works_as_expected(self):
        mock_src_mac = '01:23:45:67:89:ab'
        mock_dst_mac = 'ab:cf:ef:01:23:45'
        mock_data = b'1234'
        eth_frame = dpkt.ethernet.Ethernet()
        eth_frame.src = self.mac_utils.convert_string_mac_to_byte_array(mock_src_mac)
        eth_frame.dst = self.mac_utils.convert_string_mac_to_byte_array(mock_dst_mac)
        eth_frame.type = 2048
        eth_frame.data = mock_data

        eth_data = self.eth_frame_parser.extract_data(eth_frame)

        self.assertIsInstance(eth_data, Munch)
        self.assertEqual(eth_data.src_mac, mock_src_mac)
        self.assertEqual(eth_data.dst_mac, mock_dst_mac)
        self.assertEqual(eth_data.eth_type, 'ipv4')
        self.assertEqual(eth_data.eth_payload_size, len(mock_data))

    def test_get_eth_type_name_returns_protocol_abbrv(self):
        eth_frame = dpkt.ethernet.Ethernet()
        eth_frame.type = 2048

        self.assertEqual(self.eth_frame_parser.get_eth_type_name(eth_frame), 'ipv4')

    def test_get_eth_type_name_returns_protocol_hex_if_no_abbrv_found(self):
        eth_hex = '0x901'
        eth_frame = dpkt.ethernet.Ethernet()
        eth_frame.type = int(eth_hex, 0)

        self.assertEqual(self.eth_frame_parser.get_eth_type_name(eth_frame), eth_hex[2:])

    def test_extract_src_dst_mac_from_eth_frame_works_as_expected(self):
        mock_src_mac = '01:23:45:67:89:ab'
        mock_dst_mac = 'ab:cf:ef:01:23:45'
        eth_frame = dpkt.ethernet.Ethernet()
        eth_frame.src = self.mac_utils.convert_string_mac_to_byte_array(mock_src_mac)
        eth_frame.dst = self.mac_utils.convert_string_mac_to_byte_array(mock_dst_mac)

        src_mac, dst_mac = self.eth_frame_parser.extract_src_dest_mac_from_eth_frame(eth_frame)

        self.assertEqual(src_mac, mock_src_mac)
        self.assertEqual(dst_mac, mock_dst_mac)
