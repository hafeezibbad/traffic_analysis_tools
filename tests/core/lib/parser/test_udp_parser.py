import dpkt
from munch import Munch

from core.lib.parser.layer4_parser import UDPPacketParser
from tests.core.lib.parser.common import BasePacketParserTests


class UdpPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(UdpPacketParserTests, self).__init__(*args, **kwargs)
        self.udp_packet_parser = UDPPacketParser(config=self.config, static_data=self.static_data)

    def test_extract_data_works_as_expected(self):
        mock_data = b'12345'
        mock_src_port = 11123
        mock_dst_port = 53

        udp_packet = dpkt.udp.UDP()
        udp_packet.flags = 0x010
        udp_packet.sport = mock_src_port
        udp_packet.dport = mock_dst_port
        udp_packet.data = mock_data

        udp_data = self.udp_packet_parser.extract_data(udp_packet)

        self.assertIsInstance(udp_data, Munch)
        self.assertEqual(len(mock_data), udp_data.layer4_payload_size)
        self.assertEqual(mock_src_port, udp_data.src_port)
        self.assertEqual(mock_dst_port, udp_data.dst_port)
        self.assertTrue(udp_data.outgoing)
        self.assertEqual('dns', udp_data.layer7_proto)
