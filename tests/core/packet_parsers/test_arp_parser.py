import socket

import dpkt
from munch import Munch

from core.packet_parsers.arp_parser import ArpPacketParser
from tests.core.packet_parsers.common import BasePacketParserTests


class ArpPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(ArpPacketParserTests, self).__init__(*args, **kwargs)
        self.arp_packet_parser = ArpPacketParser(config=self.config)

    def test_extract_data_works_as_expected(self):
        src_mac = "3d:d5:31:0b:01:15"
        dst_mac = "9b:b0:7c:bb:f4:09"
        src_ip = '192.168.1.1'
        dst_ip = '192.168.1.2'

        arp_packet = dpkt.arp.ARP()
        arp_packet.sha = self.mac_utils.convert_string_mac_to_byte_array(src_mac)
        arp_packet.tha = self.mac_utils.convert_string_mac_to_byte_array(dst_mac)
        arp_packet.spa = socket.inet_aton(src_ip)
        arp_packet.tpa = socket.inet_aton(dst_ip)
        arp_packet.op = 1

        arp_data = self.arp_packet_parser.extract_data(packet=arp_packet)

        self.assertIsInstance(arp_data, Munch)
        self.assertEqual(src_mac, arp_data.arp_src_mac)
        self.assertEqual(dst_mac, arp_data.arp_dst_mac)
        self.assertEqual(1, arp_data.arp_request_src)
        self.assertEqual(src_ip, arp_data.arp_src_ip)
        self.assertEqual(dst_ip, arp_data.arp_dst_ip)
