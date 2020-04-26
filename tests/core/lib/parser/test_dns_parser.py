import socket
from unittest.mock import MagicMock

import dpkt
from netaddr.fbsocket import AF_INET6

from core.lib.parser.dns_parser import DnsPacketParser
from tests.core.lib.parser.common import BasePacketParserTests


class DnsPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(DnsPacketParserTests, self).__init__(*args, **kwargs)
        self.dns_packet_parser = DnsPacketParser(config=self.config)

    def test_extract_data_works_as_expected_for_processing_dns_queries(self):
        dns_q1 = dpkt.dns.DNS.Q()
        dns_q1.name = 'mock_qd1'
        dns_q1.type = 1
        dns_q1.cls = 1
        dns_packet = dpkt.dns.DNS()
        dns_packet.qd = [dns_q1]
        dns_packet.qr = dpkt.dns.DNS_Q
        dns_packet.op = 256
        dns_packet.rcode = dpkt.dns.DNS_RCODE_NOERR

        dns_data = self.dns_packet_parser.extract_data(dns_packet)

        self.assertEqual(dpkt.dns.DNS_Q, dns_data.dns_type)
        self.assertEqual(256, dns_data.dns_op)
        self.assertEqual(dpkt.dns.DNS_RCODE_NOERR, dns_packet.rcode)
        self.assertEqual('mock_qd1', dns_data.dns_query_domain)
        self.assertEqual('1', dns_data.dns_query_cls)
        self.assertEqual('1', dns_data.dns_query_type)

    def test_extract_data_works_as_expected_for_processing_dns_answers(self):
        dns_cname_ans = dpkt.dns.DNS.RR()
        dns_cname_ans.name = 'mock_cname'
        dns_cname_ans.ttl = 1800
        dns_cname_ans.type = dpkt.dns.DNS_CNAME
        dns_a_ans = dpkt.dns.DNS.RR()
        dns_a_ans.ip = socket.inet_aton('1.1.1.1')
        dns_a_ans.name = 'mock_aname'
        dns_a_ans.ttl = 3600
        dns_a_ans.type = dpkt.dns.DNS_A
        dns_a_ans2 = dpkt.dns.DNS.RR()
        dns_a_ans2.ip = socket.inet_aton('2.2.2.2')
        dns_a_ans2.name = 'mock_aname2'
        dns_a_ans2.ttl = 3600

        dns_packet = dpkt.dns.DNS()
        dns_packet.an = [dns_cname_ans, dns_a_ans, dns_a_ans2]
        dns_packet.qr = dpkt.dns.DNS_R
        dns_packet.op = 33152
        dns_packet.rcode = dpkt.dns.DNS_RCODE_NOERR

        dns_data = self.dns_packet_parser.extract_data(dns_packet)

        self.assertEqual(dpkt.dns.DNS_R, dns_data.dns_type)
        self.assertEqual(33152, dns_data.dns_op)
        self.assertEqual(dpkt.dns.DNS_RCODE_NOERR, dns_packet.rcode)
        self.assertEqual('mock_cname', dns_data.dns_ans_cname)
        self.assertEqual(1800, dns_data.dns_ans_cname_ttl)
        self.assertEqual('mock_aname;mock_aname2', dns_data.dns_ans_name)
        self.assertEqual('1.1.1.1;2.2.2.2', dns_data.dns_ans_ip)
        self.assertEqual(dns_a_ans.ttl, dns_data.dns_ans_ttl)

    def test_extract_data_from_dns_query_works_as_expected_for_multiple_qds(self):
        dns_q1 = dpkt.dns.DNS.Q()
        dns_q1.name = 'mock_qd1'
        dns_q1.type = 1
        dns_q1.cls = 1
        dns_q2 = dpkt.dns.DNS.Q()
        dns_q2.name = 'mock_qd2'
        dns_q2.type = 2
        dns_q2.cls = 2

        dns_packet = dpkt.dns.DNS()
        dns_packet.qd = [dns_q1, dns_q2]
        dns_data = self.dns_packet_parser.extract_data_from_dns_query(dns_packet)

        self.assertEqual('mock_qd1;mock_qd2', dns_data.dns_query_domain)
        self.assertEqual('1;2', dns_data.dns_query_type)
        self.assertEqual('1;2', dns_data.dns_query_cls)
        self.assertTrue(dns_data.dns_query_multiple_domains)

    def test_extract_data_from_dns_query_works_as_expected_for_single_qd(self):
        mock_qd1 = dpkt.dns.DNS.Q()
        mock_qd1.name = 'mock_qd1'
        mock_qd1.type = 1
        mock_qd1.cls = 1
        dns_packet = MagicMock(qd=[mock_qd1])

        dns_data = self.dns_packet_parser.extract_data_from_dns_query(dns_packet)
        self.assertEqual('mock_qd1', dns_data.dns_query_domain)
        self.assertEqual('1', dns_data.dns_query_type)
        self.assertEqual('1', dns_data.dns_query_cls)

    def test_extract_data_from_dns_ans_cname(self):
        mock_ans_1 = dpkt.dns.DNS.RR()
        mock_ans_1.type = dpkt.dns.DNS_CNAME
        mock_ans_1.ttl = 30
        mock_ans_1.name = 'mock_cname'

        dns_packet = dpkt.dns.DNS()
        dns_packet.an = [mock_ans_1]

        dns_data = self.dns_packet_parser.extract_data_from_dns_response(dns_packet)

        self.assertEqual('mock_cname', dns_data.dns_ans_cname)
        self.assertEqual(30, dns_data.dns_ans_cname_ttl)
        self.assertEqual('', dns_data.dns_ans_name)
        self.assertEqual('', dns_data.dns_ans_ip)
        self.assertEqual(None, dns_data.dns_ans_ttl)

    def test_extract_data_from_dns_A_and_AAAA_anss(self):
        mock_ans_A = dpkt.dns.DNS.RR()
        mock_ans_A.type = dpkt.dns.DNS_A
        mock_ansA_ip = '1.2.3.4'
        mock_ans_A.ip = socket.inet_aton(mock_ansA_ip)
        mock_ans_A.name = 'mock_A_name'
        mock_ans_A.ttl = 30

        mock_ans_AAAA = dpkt.dns.DNS.RR()
        mock_ans_AAAA.type = dpkt.dns.DNS_A
        mock_ans_AAAA_ip = '786b:a7d6:fc04:1d14:dfcd:5005:655e:f092'
        mock_ans_AAAA.ip = socket.inet_pton(AF_INET6, mock_ans_AAAA_ip)
        mock_ans_AAAA.name = 'mock_AAAA_name'
        mock_ans_AAAA.ttl = 60

        dns_packet = dpkt.dns.DNS()
        dns_packet.an = [mock_ans_A, mock_ans_AAAA]

        dns_data = self.dns_packet_parser.extract_data_from_dns_response(dns_packet)

        self.assertEqual('mock_A_name;mock_AAAA_name', dns_data.dns_ans_name)
        self.assertEqual('1.2.3.4;786b:a7d6:fc04:1d14:dfcd:5005:655e:f092', dns_data.dns_ans_ip)
        self.assertEqual(mock_ans_AAAA.ttl, dns_data.dns_ans_ttl)
