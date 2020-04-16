import socket
import unittest
from unittest.mock import MagicMock

import dpkt

from core.lib.dpkt_utils import DpktUtils
from core.lib.mac_utils import MacAddressUtils
from core.models.packet_data import PacketData
from core.static.utils import StaticData
from tests.core.lib.common import CONFIGURATION_OBJ


class DpktUtilsTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(DpktUtilsTest, self).__init__(*args, **kwargs)
        self.dpkt_utils = DpktUtils(config=CONFIGURATION_OBJ)
        self.mac_utils = MacAddressUtils()

    def test_extract_data_from_eth_frame_works_as_expected(self):
        src_mac = "3d:d5:31:0b:01:15"
        dst_mac = "9b:b0:7c:bb:f4:09"
        eth_frame = dpkt.ethernet.Ethernet()
        eth_frame.src = self.mac_utils.convert_string_mac_to_byte_array(src_mac)
        eth_frame.dst = self.mac_utils.convert_string_mac_to_byte_array(dst_mac)
        eth_frame.data = '1234'
        eth_frame.type = 2048

        packet_data = self.dpkt_utils.extract_data_from_eth_frame(eth_frame, PacketData())
        self.assertEqual(src_mac, packet_data.src_mac)
        self.assertEqual(dst_mac, packet_data.dst_mac)
        self.assertEqual('ipv4', packet_data.eth_type)
        self.assertNotEqual(0, packet_data.eth_frame_payload_size)

    def test_extract_data_from_layer3_packet_works_as_expected_for_ip6_packets(self):
        mock_src_ip6 = '786b:a7d6:fc04:1d14:dfcd:5005:655e:f092'
        mock_dst_ip6 = '7112:76d5:8e4f:82d7:e384:eedd:20e0:a6ab'
        ip_packet = dpkt.ip6.IP6()
        ip_packet.src = socket.inet_pton(socket.AF_INET6, mock_src_ip6)
        ip_packet.dst = socket.inet_pton(socket.AF_INET6, mock_dst_ip6)
        ip_packet.p = 2048
        ip_packet.data = b'abcdef0123456789'
        ip_packet.all_extension_headers = []

        packet_data = self.dpkt_utils.extract_data_from_layer3_protocols(
            protocol=dpkt.ethernet.ETH_TYPE_IP6,
            layer3_packet=ip_packet,
            packet_data=PacketData()
        )

        self.assertEqual(mock_src_ip6, packet_data.src_ip)
        self.assertEqual(mock_dst_ip6, packet_data.dst_ip)
        self.assertEqual(2048, packet_data.ip_proto)
        self.assertEqual(len(b'abcdef0123456789'), packet_data.ip_payload_size)

    def test_extract_data_from_layer3_packet_works_as_expected_for_ip_packets(self):
        mock_src_ip = '192.168.100.1'
        mock_dst_ip = '192.168.100.2'

        ip_packet = dpkt.ip.IP()
        ip_packet.src = socket.inet_aton(mock_src_ip)
        ip_packet.dst = socket.inet_aton(mock_dst_ip)
        ip_packet.p = 2048
        ip_packet.data = b'abcdef0123456789'
        ip_packet.ttl = 60
        ip_packet.tos = 2

        packet_data = self.dpkt_utils.extract_data_from_layer3_protocols(
            protocol=dpkt.ethernet.ETH_TYPE_IP,
            layer3_packet=ip_packet,
            packet_data=PacketData()
        )

        self.assertEqual(mock_src_ip, packet_data.src_ip)
        self.assertEqual(mock_dst_ip, packet_data.dst_ip)
        self.assertEqual(2048, packet_data.ip_proto)
        self.assertEqual(len(b'abcdef0123456789'), packet_data.ip_payload_size)
        self.assertEqual(60, packet_data.ip_ttl)
        self.assertIsInstance(packet_data.ip_more_fragment, bool)

    def test_extract_data_from_layer3_packet_works_as_expected_for_arp_packets(self):
        src_mac = "d3:d5:01:0b:31:15"
        dst_mac = "9b:b0:01:bb:7c:09"
        src_ip = '192.168.100.1'
        dst_ip = '192.168.100.2'

        arp_packet = dpkt.arp.ARP()
        arp_packet.sha = self.mac_utils.convert_string_mac_to_byte_array(src_mac)
        arp_packet.tha = self.mac_utils.convert_string_mac_to_byte_array(dst_mac)
        arp_packet.spa = socket.inet_aton(src_ip)
        arp_packet.tpa = socket.inet_aton(dst_ip)
        arp_packet.op = 2

        packet_data = self.dpkt_utils.extract_data_from_layer3_protocols(
            protocol=dpkt.ethernet.ETH_TYPE_ARP,
            layer3_packet=arp_packet,
            packet_data=PacketData()
        )

        self.assertEqual(src_mac, packet_data.arp_src_mac)
        self.assertEqual(dst_mac, packet_data.arp_dst_mac)
        self.assertEqual(2, packet_data.arp_request_src)
        self.assertEqual(src_ip, packet_data.arp_src_ip)
        self.assertEqual(dst_ip, packet_data.arp_dst_ip)

    def test_extract_data_from_layer4_packet_works_as_expected_for_tcp_packet(self):
        tcp_packet = dpkt.tcp.TCP()
        tcp_packet.sport = 50000
        tcp_packet.dport = 80
        tcp_packet.flags = 0x100
        tcp_packet.data = 'dummy_data'
        packet_data = self.dpkt_utils.extract_data_from_layer4_protocols(
            protocol=dpkt.ip.IP_PROTO_TCP,
            layer4_packet=tcp_packet,
            packet_data=PacketData()
        )

        self.assertTrue(packet_data.outgoing)
        self.assertEqual(80, packet_data.dst_port)
        self.assertEqual(50000, packet_data.src_port)
        self.assertNotEqual(0, packet_data.layer4_payload_size)
        self.assertEqual(80, packet_data.layer7_proto)
        self.assertEqual('http', packet_data.layer7_proto_name)

    def test_extract_data_from_layer4_packet_works_as_expected_for_udp_packet(self):
        udp_packet = dpkt.udp.UDP()
        udp_packet.sport = 50000
        udp_packet.dport = 800
        udp_packet.data = b'dummy_data'

        packet_data = self.dpkt_utils.extract_data_from_layer4_protocols(
            protocol=dpkt.ip.IP_PROTO_UDP,
            layer4_packet=udp_packet,
            packet_data=PacketData()
        )

        self.assertTrue(packet_data.outgoing)
        self.assertEqual(800, packet_data.dst_port)
        self.assertEqual(50000, packet_data.src_port)
        self.assertNotEqual(0, packet_data.layer4_payload_size)
        self.assertEqual(800, packet_data.layer7_proto)
        self.assertEqual('mdbe', packet_data.layer7_proto_name)

    @unittest.mock.patch('core.lib.dpkt_parsers.dns_parser.DnsPacketParser.load_dns_packet_from_udp_packet')
    def test_extract_data_from_layer7_packet_works_for_dns_packet(self, dns_mock):
        udp_dns_packet = dpkt.udp.UDP()
        udp_dns_packet.dport = 53

        mock_ans_1 = dpkt.dns.DNS.RR()
        mock_ans_1.type = dpkt.dns.DNS_CNAME
        mock_ans_1.ttl = 60
        mock_ans_1.name = 'mock_cname_ans'
        dns_packet = MagicMock(
            an=[mock_ans_1],
            qr=dpkt.dns.DNS_R
        )
        dns_mock.return_value = dns_packet
        packet_data = PacketData(dst_port=53)
        packet_data = self.dpkt_utils.extract_data_from_layer7_protocols(udp_dns_packet, packet_data)

        self.assertEqual(mock_ans_1.name, packet_data.dns_ans_cname)
        self.assertEqual(mock_ans_1.ttl, packet_data.dns_ans_cname_ttl)
        self.assertEqual('', packet_data.dns_ans_name)
        self.assertEqual('', packet_data.dns_ans_ip)
        self.assertEqual('', packet_data.dns_ans_ttl)

    @unittest.mock.patch('core.lib.dpkt_parsers.ntp_parser.NtpPacketParser.load_ntp_packet_from_udp_packet')
    def test_extract_data_from_layer7_packet_works_for_ntp_packet(self, ntp_mock):
        udp_ntp_packet = dpkt.udp.UDP()
        udp_ntp_packet.dport = 123

        ntp_packet = MagicMock(
            id=socket.inet_aton('1.2.3.4'),
            mode=1,
            stratum=2,
            interval=5
        )

        ntp_mock.return_value = ntp_packet

        packet_data = PacketData(dst_port=123)
        packet_data = self.dpkt_utils.extract_data_from_layer7_protocols(udp_ntp_packet, packet_data)

        self.assertEqual('1.2.3.4', packet_data.ntp_reference_id)
        self.assertEqual(1, packet_data.ntp_mode)
        self.assertEqual(2, packet_data.ntp_stratum)
        self.assertEqual(5, packet_data.ntp_interval)
