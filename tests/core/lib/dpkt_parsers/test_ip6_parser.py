import socket

import dpkt

from core.lib.dpkt_parsers.ip6_parser import Ip6PacketParser
from tests.core.lib.dpkt_parsers.common import BasePacketParserTests


class Ip6PacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(Ip6PacketParserTests, self).__init__(*args, **kwargs)
        self.ip6_packet_parser = Ip6PacketParser(config=self.config)

    def test_extract_data_works_as_expected(self):
        mock_src_ip6 = '786b:a7d6:fc04:1d14:dfcd:5005:655e:f092'
        mock_dst_ip6 = '7112:76d5:8e4f:82d7:e384:eedd:20e0:a6ab'
        ip_packet = dpkt.ip6.IP6()

        ip_packet.src = socket.inet_pton(socket.AF_INET6, mock_src_ip6)
        ip_packet.dst = socket.inet_pton(socket.AF_INET6, mock_dst_ip6)
        ip_packet.p = 2048
        ip_packet.data = b'1234'
        ip_packet.tos = 1
        ip_packet.all_extension_headers = []

        ip6_data = self.ip6_packet_parser.extract_data(ip_packet)

        self.assertEqual(mock_src_ip6, ip6_data.src_ip)
        self.assertEqual(mock_dst_ip6, ip6_data.dst_ip)
        self.assertEqual(2048, ip6_data.ip_proto)
        self.assertEqual(len(b'1234'), ip6_data.ip_payload_size)

    def test_extract_src_dest_ip_returns_src_dest_ip(self):
        mock_src_ip6 = '786b:a7d6:fc04:1d14:dfcd:5005:655e:f092'
        mock_dst_ip6 = '7112:76d5:8e4f:82d7:e384:eedd:20e0:a6ab'
        ip_packet = dpkt.ip6.IP6()
        ip_packet.src = socket.inet_pton(socket.AF_INET6, mock_src_ip6)
        ip_packet.dst = socket.inet_pton(socket.AF_INET6, mock_dst_ip6)

        extracted_src_ip6, extracted_dst_ip6 = self.ip6_packet_parser.extract_src_dest_ip(ip_packet)

        self.assertEqual(mock_src_ip6, extracted_src_ip6)
        self.assertEqual(mock_dst_ip6, extracted_dst_ip6)
