import socket

import dpkt
from munch import Munch

from core.lib.dpkt_parsers.ip_parser import IpPacketParser
from tests.core.lib.dpkt_parsers.common import BasePacketParserTests


class IpPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(IpPacketParserTests, self).__init__(*args, **kwargs)
        self.ip_packet_parser = IpPacketParser(config=self.config)

    def test_extract_data_works_as_expected(self):
        mock_src_ip = '192.168.1.1'
        mock_dst_ip = '192.168.1.2'

        ip_packet = dpkt.ip.IP()
        ip_packet.src = socket.inet_aton(mock_src_ip)
        ip_packet.dst = socket.inet_aton(mock_dst_ip)
        ip_packet.p = 2048
        ip_packet.data = b'1234'
        ip_packet.ttl = 30
        ip_packet.tos = 1
        ip_packet.opts = b''
        ip_packet.flags = 0x400

        ip_data = self.ip_packet_parser.extract_data(ip_packet)
        self.assertIsInstance(ip_data, Munch)

        self.assertEqual(mock_src_ip, ip_data.src_ip)
        self.assertEqual(mock_dst_ip, ip_data.dst_ip)
        self.assertEqual('2048', ip_data.ip_proto)
        self.assertEqual(len(b'1234'), ip_data.ip_payload_size)
        self.assertEqual(30, ip_data.ip_ttl)
        self.assertFalse(ip_data.ip_do_not_fragment)
        self.assertIsInstance(ip_data.ip_more_fragment, bool)
        self.assertEqual('', ip_data.ip_opts)

    def test_extract_src_dest_ip_returns_src_dest_ip(self):
        mock_src_ip = '192.168.1.1'
        mock_dst_ip = '192.168.1.2'
        ip_packet = dpkt.ip.IP()
        ip_packet.src = socket.inet_aton(mock_src_ip)
        ip_packet.dst = socket.inet_aton(mock_dst_ip)

        extracted_src_ip, extracted_dst_ip = self.ip_packet_parser.extract_src_dest_ip(ip_packet)

        self.assertEqual(mock_src_ip, extracted_src_ip)
        self.assertEqual(mock_dst_ip, extracted_dst_ip)

    def test_ip_options_parsing(self):
        ip_options = b'\x94\x04\x00\x00'
        options_str = self.ip_packet_parser.parse_ip_options(ip_options)
        self.assertEqual(options_str, 'RTRALT')
