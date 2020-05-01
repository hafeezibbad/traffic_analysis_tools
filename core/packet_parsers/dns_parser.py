import logging
from typing import Optional

import dpkt
from dpkt.dns import DNS
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils


class DnsPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_utils = IpAddrUtils()

    @staticmethod
    def load_dns_packet_from_ip_packet(ip_packet: IP) -> Optional[DNS]:
        try:
            udp_packet = UDP(ip_packet.data)
            return DnsPacketParser.load_dns_packet_from_udp_packet(udp_packet)

        except BaseException as ex:
            logging.warning('Can not extract DNS packet from UDP packet. Error: {}'.format(ex))
            raise ex

    @staticmethod
    def load_dns_packet_from_udp_packet(udp_packet: UDP) -> Optional[DNS]:
        try:
            return DNS(udp_packet.data)

        except Exception as ex:
            logging.warning('Can not extract DNS packet from UDP packet. Error: {}'.format(ex))
            raise ex

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
            logging.warning('Unable to extract DNS from `{}`. Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def extract_data_from_dns_query(self, dns_packet: DNS) -> Munch:
        data = Munch()
        try:
            if len(dns_packet.qd) > 1:
                if self.config.use_numeric_values is True:
                    data.dns.query_multiple_domains = 1
                else:
                    data.dns_query_multiple_domains = True

            data.dns_query_domain = self.config.FieldDelimiter.join([q.name for q in dns_packet.qd])
            data.dns_query_type = self.config.FieldDelimiter.join([str(q.type) for q in dns_packet.qd])
            data.dns_query_cls = self.config.FieldDelimiter.join([str(q.cls) for q in dns_packet.qd])

        except BaseException as ex:
            logging.warning('Unable to extract DNS from `{}`. Error: `{}`'.format(type(dns_packet), ex))
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
            # We are using only max value because in experience ttl is same even if there is separate ttl for each IP
            # address in DNS response
            if dns_ans_ttl:
                data.dns_ans_ttl = max(dns_ans_ttl)
            else:
                data.dns_ans_ttl = None

            if self.config.use_numeric_values is True:
                dns_ans_ip_list = map(self.ip_utils.ip_to_int, dns_ans_ip_list)
            data.dns_ans_ip = self.config.FieldDelimiter.join([str(ip) for ip in dns_ans_ip_list])

        except Exception as ex:
            logging.error('Unable to process dns answers packet. Error: {}'.format(ex))
            raise ex

        return data
