import logging
from typing import Tuple

from dpkt.ethernet import Ethernet
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.mac_utils import MacAddressUtils
from core.static.utils import StaticData


class EthernetFrameParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ether_type_data = StaticData.load_ether_types_data()
        self.mac_utils = MacAddressUtils()

    def extract_data(self, packet: Ethernet) -> Munch:
        data = Munch()
        try:
            data.src_mac, data.dst_mac = self.extract_src_dest_mac_from_eth_frame(eth_frame=packet)
            data.eth_type = self.get_eth_type_name(packet)
            data.eth_frame_payload_size = len(packet.data)

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(packet), ex))

        return data

    def get_eth_type_name(self, eth_frame: Ethernet) -> str:
        eth_type = str(hex(eth_frame.type)[2:])
        eth_type_str = self.ether_type_data.get(eth_type, {}).get('protocol_abbrv', '').lower()
        if not eth_type_str:
            eth_type_str = eth_type

        return eth_type_str

    def extract_src_dest_mac_from_eth_frame(self, eth_frame: Ethernet) -> Tuple:
        return self.mac_utils.convert_hexadecimal_mac_to_readable_mac(eth_frame.src), \
               self.mac_utils.convert_hexadecimal_mac_to_readable_mac(eth_frame.dst)
