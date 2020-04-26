import socket
import unittest
from unittest.mock import MagicMock

import dpkt
from dpkt.dns import DNS
from dpkt.ntp import NTP

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
        self.assertNotEqual(0, packet_data.eth_payload_size)

    def test_extract_data_from_layer3_packet_works_as_expected_for_ip6_packets(self):
        mock_src_ip6 = '786b:a7d6:fc04:1d14:dfcd:5005:655e:f092'
        mock_dst_ip6 = '7112:76d5:8e4f:82d7:e384:eedd:20e0:a6ab'
        ip_packet = dpkt.ip6.IP6()
        ip_packet.src = socket.inet_pton(socket.AF_INET6, mock_src_ip6)
        ip_packet.dst = socket.inet_pton(socket.AF_INET6, mock_dst_ip6)
        ip_packet.p = 2048
        ip_packet.data = b'abcdef0123456789'
        ip_packet.all_extension_headers = []

        packet_data = self.dpkt_utils.extract_data_from_layer3_packet(ip_packet, PacketData())

        self.assertEqual(mock_src_ip6, packet_data.src_ip)
        self.assertEqual(mock_dst_ip6, packet_data.dst_ip)
        self.assertEqual(ip_packet.p, packet_data.ip_proto)
        self.assertEqual(len(ip_packet.data), packet_data.ip_payload_size)

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

        packet_data = self.dpkt_utils.extract_data_from_layer3_packet(
            layer3_packet=ip_packet,
            packet_data=PacketData()
        )

        self.assertEqual(mock_src_ip, packet_data.src_ip)
        self.assertEqual(mock_dst_ip, packet_data.dst_ip)
        self.assertEqual(str(ip_packet.p), packet_data.ip_proto)
        self.assertEqual(len(ip_packet.data), packet_data.ip_payload_size)
        self.assertEqual(ip_packet.ttl, packet_data.ip_ttl)
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

        packet_data = self.dpkt_utils.extract_data_from_layer3_packet(
            layer3_packet=arp_packet,
            packet_data=PacketData()
        )

        self.assertEqual(src_mac, packet_data.arp_src_mac)
        self.assertEqual(dst_mac, packet_data.arp_dst_mac)
        self.assertEqual(arp_packet.op, packet_data.arp_request_src)
        self.assertEqual(src_ip, packet_data.arp_src_ip)
        self.assertEqual(dst_ip, packet_data.arp_dst_ip)

    def test_extract_data_from_layer4_packet_works_as_expected_for_tcp_packet(self):
        tcp_packet = dpkt.tcp.TCP()
        tcp_packet.sport = 50000
        tcp_packet.dport = 80
        tcp_packet.flags = 0x100
        tcp_packet.data = 'dummy_data'
        packet_data = self.dpkt_utils.extract_data_from_layer4_packet(
            layer4_packet=tcp_packet,
            packet_data=PacketData()
        )

        self.assertTrue(packet_data.outgoing)
        self.assertEqual(80, packet_data.dst_port)
        self.assertEqual(50000, packet_data.src_port)
        self.assertNotEqual(0, packet_data.layer4_payload_size)
        self.assertEqual('http', packet_data.layer7_proto)  # HTTP uses port 80

    def test_extract_data_from_layer4_packet_works_as_expected_for_udp_packet(self):
        udp_packet = dpkt.udp.UDP()
        udp_packet.sport = 50000
        udp_packet.dport = 800
        udp_packet.data = b'dummy_data'

        packet_data = self.dpkt_utils.extract_data_from_layer4_packet(
            layer4_packet=udp_packet,
            packet_data=PacketData()
        )

        self.assertTrue(packet_data.outgoing)
        self.assertEqual(udp_packet.dport, packet_data.dst_port)
        self.assertEqual(udp_packet.sport, packet_data.src_port)
        self.assertNotEqual(0, packet_data.layer4_payload_size)
        self.assertEqual('mdbe', packet_data.layer7_proto)  # mdbe uses port 800

    def test_extract_data_from_layer7_packet_works_for_dns_packet(self):
        mock_ans_1 = dpkt.dns.DNS.RR()
        mock_ans_1.type = dpkt.dns.DNS_CNAME
        mock_ans_1.ttl = 60
        mock_ans_1.name = 'mock_cname_ans'
        mock_dns_packet = DNS()
        mock_dns_packet.an = [mock_ans_1]
        mock_dns_packet.qr = dpkt.dns.DNS_R

        packet_data = self.dpkt_utils.extract_data_from_layer7_packet(mock_dns_packet, PacketData())

        self.assertEqual(mock_ans_1.name, packet_data.dns_ans_cname)
        self.assertEqual(mock_ans_1.ttl, packet_data.dns_ans_cname_ttl)
        self.assertIsNone(packet_data.dns_ans_name)
        self.assertIsNone(packet_data.dns_ans_ip)
        self.assertIsNone(packet_data.dns_ans_ttl)

    def test_extract_data_from_layer7_packet_works_for_ntp_packet(self):
        ntp_packet = NTP()
        mock_ntp_reference = '1.2.3.4'
        ntp_packet.id = socket.inet_aton(mock_ntp_reference)
        ntp_packet.mode = 1
        ntp_packet.stratum = 2
        ntp_packet.interval = 5

        packet_data = PacketData(dst_port=123)
        packet_data = self.dpkt_utils.extract_data_from_layer7_packet(ntp_packet, packet_data)

        self.assertEqual(mock_ntp_reference, packet_data.ntp_reference_id)
        self.assertEqual(ntp_packet.mode, packet_data.ntp_mode)
        self.assertEqual(ntp_packet.stratum, packet_data.ntp_stratum)
        self.assertEqual(ntp_packet.interval, packet_data.ntp_interval)

    def test_extract_data_from_ntp_packet_works_as_expected(self):
        ntp_packet = NTP()
        mock_ntp_reference = '1.2.3.4'
        ntp_packet.id = socket.inet_aton(mock_ntp_reference)
        ntp_packet.mode = 1
        ntp_packet.stratum = 2
        ntp_packet.interval = 5

        data = self.dpkt_utils.extract_data_from_ntp_packet(ntp_packet)

        self.assertEqual(mock_ntp_reference, data.ntp_reference_id)
        self.assertEqual(ntp_packet.mode, data.ntp_mode)
        self.assertEqual(ntp_packet.stratum, data.ntp_stratum)
        self.assertEqual(ntp_packet.interval, data.ntp_interval)

    def test_extract_data_from_dns_packet_works_as_expected(self):
        mock_ans_1 = dpkt.dns.DNS.RR()
        mock_ans_1.type = dpkt.dns.DNS_CNAME
        mock_ans_1.ttl = 60
        mock_ans_1.name = 'mock_cname_ans'
        mock_dns_packet = DNS()
        mock_dns_packet.an = [mock_ans_1]
        mock_dns_packet.qr = dpkt.dns.DNS_R

        data = self.dpkt_utils.extract_data_from_dns_packet(mock_dns_packet)

        self.assertEqual(mock_ans_1.name, data.dns_ans_cname)
        self.assertEqual(mock_ans_1.ttl, data.dns_ans_cname_ttl)
        self.assertEqual('', data.dns_ans_name)
        self.assertEqual('', data.dns_ans_ip)
        self.assertIsNone(data.dns_ans_ttl)
