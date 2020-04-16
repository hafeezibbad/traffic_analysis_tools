import logging
from typing import Optional

from dpkt.igmp import IGMP
from dpkt.ip import IP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils
from core.models.packet_data import PacketData


class IgmpPacketParser(PacketParserInterface):
    # Use Scipy: https://github.com/secdev/scapy/blob/master/scapy/contrib/igmp.py
    def __init__(self, config: ConfigurationData, *args, **kwargs):
        self.config = config
        self.ip_addr_utils = IpAddrUtils()

    @staticmethod
    def load_igmp_packet_from_ip_packet(ip_packet: IP) -> Optional[IGMP]:
        igmp_packet = None
        try:
            igmp_packet = IGMP(ip_packet.data)

        except BaseException as ex:
            logging.warning('Can not extract IGMP packet from IP Packet. Error: `{}`'.format(ex))

        return igmp_packet

    def extract_data(self, igmp_packet: IGMP) -> Munch:
        data = Munch()
        if igmp_packet is None:
            return data

        data.igmp_type = igmp_packet.type
        data.igmp_addr = self.ip_addr_utils.inet_to_str(igmp_packet.group)

        return data
