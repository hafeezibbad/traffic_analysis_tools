import logging
from typing import Optional

import dpkt
from dpkt.dns import DNS
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils


class DnsPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_utils = IpAddrUtils()

    @staticmethod
    def load_dns_packet_from_ip_packet(ip_packet: IP) -> Optional[DNS]:
        dns = None
        try:
            udp_packet = UDP(ip_packet.data)
            dns = DnsPacketParser.load_dns_packet_from_udp_packet(udp_packet)

        except BaseException as ex:
            logging.warning('Can not extract DNS packet from UDP packet. Error: {}'.format(ex))

        return dns

    @staticmethod
    def load_dns_packet_from_udp_packet(udp_packet: UDP) -> Optional[DNS]:
        dns = None
        try:
            dns = DNS(udp_packet.data)

        except dpkt.dpkt.NeedData:
            logging.warning('Not enough data to extract DNS packet from UDP packet')

        except Exception as ex:
            logging.warning('Can not extract DNS packet from UDP packet. Error: {}'.format(ex))

        return dns

    def extract_data(self, packet: DNS) -> Munch:
        data = Munch()
        try:
            data.dns_type = packet.qr
            data.dns_op = packet.op
            data.dns_rcode = packet.rcode

            if data.dns_type == dpkt.dns.DNS_Q:
                # This is a DNS query
                data.update(self.extract_data_from_dns_query(packet))

            elif data.dns_type == dpkt.dns.DNS_R:
                # This is a DNS response
                data.update(self.extract_data_from_dns_response(packet))

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def extract_data_from_dns_query(self, dns_packet: DNS) -> Munch:
        data = Munch()
        try:
            if len(dns_packet.qd) > 1:
                data.dns_query_multiple_domains = True

            data.dns_query_domain = self.config.FieldDelimiter.join([q.name for q in dns_packet.qd])
            data.dns_query_type = self.config.FieldDelimiter.join([str(q.type) for q in dns_packet.qd])
            data.dns_query_cls = self.config.FieldDelimiter.join([str(q.cls) for q in dns_packet.qd])

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(dns_packet), ex))
            raise ex

        return data

    def extract_data_from_dns_response(self, dns_packet: DNS) -> Munch:
        data = Munch()
        # Process and get responses based on record types listed in
        # http://en.wikipedia.org/wiki/List_of_DNS_record_types
        dns_ans_ip_list = []
        dns_ans_name_list = []
        dns_ans_ttl = []

        try:
            for answer in dns_packet.an:
                data.dns_ans_type = answer.type
                if answer.type == dpkt.dns.DNS_CNAME:
                    data.dns_ans_cname = answer.name
                    data.dns_ans_cname_ttl = answer.ttl

                elif answer.type == dpkt.dns.DNS_A or answer.type == dpkt.dns.DNS_AAAA:
                    if hasattr(answer, 'ip'):
                        dns_ans_ip_list.append(self.ip_utils.inet_to_str(answer.ip))
                    dns_ans_name_list.append(answer.name)
                    dns_ans_ttl.append(answer.ttl)
                # TODO: Handle other types of dns answers:
                # Ref: https://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html#dns-answer

            data.dns_ans_name = self.config.FieldDelimiter.join([name for name in dns_ans_name_list])
            data.dns_ans_ip = self.config.FieldDelimiter.join([ip for ip in dns_ans_ip_list])
            data.dns_ans_ttl = self.config.FieldDelimiter.join([str(ttl) for ttl in dns_ans_ttl])

        except Exception as ex:
            logging.error('Unable to process dns answers packet. Error: {}'.format(ex))

        return data
