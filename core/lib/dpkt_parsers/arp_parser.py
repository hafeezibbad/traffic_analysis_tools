import logging

from dpkt.arp import ARP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils
from core.lib.mac_utils import MacAddressUtils


class ArpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_utils = IpAddrUtils()
        self.mac_utils = MacAddressUtils()

    def extract_data(self, packet: ARP) -> Munch:
        data = Munch()
        try:
            data.arp_request_src = packet.op
            data.arp_src_mac = self.mac_utils.convert_hexadecimal_mac_to_readable_mac(packet.sha)
            data.arp_src_ip = self.ip_utils.inet_to_str(packet.spa)
            data.arp_dst_mac = self.mac_utils.convert_hexadecimal_mac_to_readable_mac(packet.tha)
            data.arp_dst_ip = self.ip_utils.inet_to_str(packet.tpa)

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(packet), ex))
            raise ex

        return data
