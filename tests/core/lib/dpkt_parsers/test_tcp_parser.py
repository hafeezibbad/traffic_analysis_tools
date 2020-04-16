import dpkt
from munch import Munch

from core.lib.dpkt_parsers.layer4_parser import TcpPacketParser
from core.models.packet_data import PacketData
from tests.core.lib.dpkt_parsers.common import BasePacketParserTests


class TcpPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(TcpPacketParserTests, self).__init__(*args, **kwargs)
        self.tcp_packet_parser = TcpPacketParser(config=self.config, static_data=self.static_data)

    def test_extract_flags_works_as_expected(self):
        tcp_packet = dpkt.tcp.TCP()
        tcp_packet.flags = 0x10

        flag_data = self.tcp_packet_parser.extract_flags(tcp_packet)

        self.assertIsInstance(flag_data, dict)
        self.assertFalse(flag_data.tcp_fin_flag)
        self.assertFalse(flag_data.tcp_syn_flag)
        self.assertFalse(flag_data.tcp_rst_flag)
        self.assertFalse(flag_data.tcp_psh_flag)
        self.assertTrue(flag_data.tcp_ack_flag)
        self.assertFalse(flag_data.tcp_urg_flag)
        self.assertFalse(flag_data.tcp_ece_flag)
        self.assertFalse(flag_data.tcp_cwr_flag)

    def test_extract_data_works_as_expected(self):
        mock_data = b'12345'
        mock_src_port = 11123
        mock_dst_port = 53

        tcp_packet = dpkt.tcp.TCP()
        tcp_packet.flags = 0x010
        tcp_packet.sport = mock_src_port
        tcp_packet.dport = mock_dst_port
        tcp_packet.data = mock_data

        tcp_data = self.tcp_packet_parser.extract_data(tcp_packet)

        self.assertEqual(len(mock_data), tcp_data.layer4_payload_size)
        self.assertEqual(mock_src_port, tcp_data.src_port)
        self.assertEqual(mock_dst_port, tcp_data.dst_port)
        self.assertTrue(tcp_data.outgoing)
        self.assertEqual(mock_dst_port, tcp_data.layer7_proto)
        self.assertEqual('dns', tcp_data.layer7_proto_name)
        self.assertTrue(tcp_data.tcp_ack_flag)
