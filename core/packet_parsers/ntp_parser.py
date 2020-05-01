import logging
from typing import Optional, Union

import dpkt
from dpkt.ip import IP
from dpkt.ntp import NTP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils


class NtpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_utils = IpAddrUtils()

    @staticmethod
    def load_ntp_packet_from_ip_packet(ip_packet: IP) -> Optional[NTP]:
        try:
            udp_packet = UDP(ip_packet.data)
            return NtpPacketParser.load_ntp_packet_from_udp_packet(udp_packet)

        except BaseException as ex:
            logging.warning('Can not extract NTP packet from UDP packet. Error: `%s`', ex)
            raise ex

    @staticmethod
    def load_ntp_packet_from_udp_packet(udp_packet: UDP) -> Optional[NTP]:
        try:
            return NTP(udp_packet.data)

        except dpkt.dpkt.NeedData:
            logging.warning('Not enough data to extract NTP packet from UDP packet')

        except BaseException as ex:
            logging.warning('Can not extract NTP packet from UDP packet. Error: `%s`', ex)
            raise ex

    def extract_data(self, packet: NTP) -> Munch:
        data = Munch()
        try:
            data.ntp_mode = packet.mode
            data.ntp_interval = packet.interval
            data.ntp_stratum = packet.stratum
            data.ntp_reference_id = self.resolve_ntp_reference(packet)

        except BaseException as ex:
            logging.warning('Unable to extract NTP from `%s`. Error: `%s`', type(packet), ex)
            raise ex

        return data

    def resolve_ntp_reference(self, packet: NTP) -> Union[int, str]:
        reference_id = self.ip_utils.inet_to_str(packet.id)
        if reference_id is None:
            # Could not parse NTP REFID, probably it is a string
            return packet.id

        if reference_id == '0.0.0.0':
            # REFID is NULL but dpkt considers it as b'\x00\x00\x00\x00'
            return ''

        if self.config.use_numeric_values is True:
            return self.ip_utils.ip_to_int(reference_id)

        return reference_id
