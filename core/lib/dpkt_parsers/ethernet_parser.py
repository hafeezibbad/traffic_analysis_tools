import logging
from typing import Tuple, Union

from dpkt.ethernet import Ethernet
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.mac_utils import MacAddressUtils
from core.static.utils import StaticData


class EthernetFrameParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None):
        self.config = config
        self.mac_utils = MacAddressUtils()
        self.static_data = static_data or StaticData()

    def extract_data(self, packet: Ethernet) -> Munch:
        data = Munch()
        try:
            data.src_mac, data.dst_mac = self.extract_src_dest_mac_from_eth_frame(eth_frame=packet)
            data.eth_type = self.get_eth_type_name(packet)
            data.eth_payload_size = len(packet.data)

        except BaseException as ex:
            logging.warning('Unable to extract ETH from `{}`. Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def get_eth_type_name(self, eth_frame: Ethernet) -> Union[int, str]:
        eth_type = str(hex(eth_frame.type)[2:])

        eth_type_str = self.static_data.ether_types_data.get(eth_type, {}).get('protocol_abbrv', '').lower()
        if not eth_type_str:
            eth_type_str = eth_type

        return eth_type_str

    def extract_src_dest_mac_from_eth_frame(self, eth_frame: Ethernet) -> Tuple:
        src_mac = self.mac_utils.convert_hexadecimal_mac_to_readable_mac(eth_frame.src)
        dst_mac = self.mac_utils.convert_hexadecimal_mac_to_readable_mac(eth_frame.dst)

        return src_mac, dst_mac
