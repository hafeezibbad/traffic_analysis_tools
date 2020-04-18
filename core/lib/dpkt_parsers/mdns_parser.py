import logging
from typing import Optional

import dpkt
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.dpkt_parsers.mdns_unpacker import Mdns
from core.models.packet_data import PacketData


class MdnsPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    @staticmethod
    def load_mdns_packet_from_ip_packet(ip_packet: IP) -> Optional[Mdns]:
        try:
            udp_packet = UDP(ip_packet.data)
            return MdnsPacketParser.load_mdns_packet_from_udp_packet(udp_packet)

        except BaseException as ex:
            logging.warning('Can not extract mDNS packet from IP packet. Error: {}'.format(ex))
            raise ex

    @staticmethod
    def load_mdns_packet_from_udp_packet(udp_packet: IP) -> Optional[Mdns]:
        try:
            return Mdns(udp_packet.data)

        except BaseException as ex:
            logging.warning('Can not extract mDNS packet from IP packet. Error: {}'.format(ex))
            raise ex

    def is_mdns_packet_valid_for_processing(self, mdns_packet: Mdns) -> bool:
        if mdns_packet.is_response() is False:
            logging.debug('mDNS packet is not a response')

            return False

        if mdns_packet.is_query() is False:
            logging.debug('mDNS packet is not a standard mDNS query message')

            return False

        if mdns_packet.has_error() is True:
            logging.warning('mDNS packet has an error code. Error: {}'.format(mdns_packet.flags))

            return False

        return True

    def get_dns_hostname_from_ptr_record(self, ptr_record: str) -> Optional[str]:
        if ptr_record is None:
            return None

        if "_tcp.local" in ptr_record:
            logging.debug('mdns_hostname ignore _tcp.local {}'.format(ptr_record))
            return None

        if "_udp.local" in ptr_record:
            logging.debug("mdns_hostname ignoring _udp.local {}".format(ptr_record))
            return None

        dns_hostname = ptr_record
        if dns_hostname[-6:].lower() == ".local":
            # .local is not useful/related to device name.
            dns_hostname = dns_hostname[:-6]

        return dns_hostname

    def find_hostname_from_reverse_arp_pointer_in_dns(self, mdns_answers) -> Optional[str]:
        mdns_hostname = None

        for dns_record in mdns_answers:

            record_type = dns_record.get('TYPE')
            if record_type is None:
                logging.warning(
                    'MDNS_PACKET_PARSING_EXCEPTION',
                    message='DNS record for answer `{}` does not have `TYPE` information'.format(dns_record)
                )

            if record_type == dpkt.dns.DNS_PTR:
                hostname = self.get_dns_hostname_from_ptr_record(ptr_record=dns_record["PTRDNAME"])
                if hostname is not None:
                    mdns_hostname = hostname

        return mdns_hostname

    def find_service_from_dns_record(self, dns_record) -> Optional[str]:
        record_type = dns_record.get('TYPE')
        record_name = dns_record.get('NAME')

        if record_type is None or record_name is None:
            logging.warning(
                'MDNS_PACKET_PARSING_EXCEPTION',
                message='Given DNS_RECORD is not of type `dpkt.dns.DNS_PTR`',
            )

        if record_type == dpkt.dns.DNS_PTR and record_name == "_services._dns-sd._udp.local":
            return dns_record['PTRDNAME']

        return None

    def find_dns_services_from_dns_packet(self, dns_packet):
        dns_services = []

        for dns_record in dns_packet.answers:
            service = self.find_service_from_dns_record(dns_record=dns_record)

            if service is not None:
                dns_services.append(service)

        return dns_services

    def find_hostname_and_services_from_dns_packet(self, mdns_packet):
        mdns_hostname = None
        mdns_services = []

        if len(mdns_packet.questions) < 1:
            logging.warning(
                'MDNS_PACKET_PARSING_EXCEPTION',
                message='mDNS packet does not have any questions'
            )

            return mdns_hostname, mdns_services

        qname_question = mdns_packet.questions[0].get("QNAME")
        if qname_question is None:
            logging.warning(
                'MDNS_PACKET_PARSING_EXCEPTION',
                message='mDNS packet questions do not have any QNAME key',
            )

            return mdns_hostname, mdns_services

        if ".in-addr.arpa" in mdns_packet.questions[0]["QNAME"]:
            mdns_hostname = self.find_hostname_from_reverse_arp_pointer_in_dns(mdns_answers=mdns_packet.answers)

        elif "_services._dns-sd._udp.local" in mdns_packet.questions[0]["QNAME"]:
            mdns_services = self.find_dns_services_from_dns_packet(dns_packet=mdns_packet)

        else:
            logging.debug("mDNS unknown question: %s\n" % mdns_packet.questions[0]["QNAME"])

        return mdns_hostname, mdns_services

    def find_hostname_and_service_from_dns_record(self, dns_record):
        hostname = None
        service = None

        record_name = dns_record.get('NAME')
        if record_name is None:
            logging.warning(
                'MDNS_PACKET_PARSING_EXCEPTION',
                message='DNS record `{}` does not have expected fields'.format(dns_record)
            )
            return None, None

        if record_name == "_services._dns-sd._udp.local":
            service = dns_record.get("PTRDNAME")

        if 'in-addr.arpa' in record_name:
            hostname = self.get_dns_hostname_from_ptr_record(ptr_record=dns_record.get("PTRDNAME"))

        return hostname, service

    def find_hostname_and_services_from_complex_dns_packet(self, mdns_packet):
        dns_hostname = None
        dns_services = []

        for dns_record in mdns_packet.answers:
            record_type = dns_record.get('TYPE')
            if record_type is None:
                logging.warning(
                    'MDNS_PACKET_PARSING_EXCEPTION',
                    message='DNS record `{}` does not have `TYPE` fields'.format(dns_record)
                )
                return dns_hostname, dns_services

            if record_type == dpkt.dns.DNS_PTR:
                hostname, service = self.find_hostname_and_service_from_dns_record(dns_record=dns_record)

                if service is not None:
                    dns_services.append(service)

                if hostname is not None:
                    dns_hostname = hostname

            elif record_type == dpkt.dns.DNS_SRV:
                hostname = self.get_dns_hostname_from_ptr_record(ptr_record=dns_record["TARGET"])

                if hostname is not None:
                    dns_hostname = hostname

        return dns_hostname, dns_services

    def get_mdns_packet_type(self, mdns_packet: Mdns) -> int:
        if mdns_packet.is_query() is True:
            return 1

        if mdns_packet.is_response() is True:
            return 2

        return -1

    def extract_data(self, packet: Mdns) -> Munch:
        data = Munch()
        try:
            if self.is_mdns_packet_valid_for_processing(packet) is False:
                return data

            data.mdns_packet_type = self.get_mdns_packet_type(mdns_packet=packet)

            if packet.question_count == 1:
                data.mdns_hostname, data.mdns_services = self.find_hostname_and_services_from_dns_packet(packet)

            elif packet.question_count != 1:
                logging.debug("Expecting 1 mDNS question, got {}".format(packet.question_count))
                # This is a seriously fucked up poor son of a bitch packet, but we do not care. We just go on.
                data.mdns_hostname, data.mdns_services = self.find_hostname_and_services_from_complex_dns_packet(packet)

        except BaseException as ex:
            logging.warning('Unable to extract data from DNS packet `{}`.Error: `{}`'.format(packet, ex))
            raise ex

        return data
