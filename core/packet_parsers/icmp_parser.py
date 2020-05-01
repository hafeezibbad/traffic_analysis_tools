import logging
from typing import Union

from dpkt.icmp import ICMP
from dpkt.icmp6 import ICMP6
from munch import Munch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface
from core.static.icmp6_data import ICMP6_TYPES
from core.static.icmp_data import ICMP_TYPES


class BaseIcmpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData, *args, **kwargs):
        self.config = config

    def extract_data(self, packet: Union[ICMP, ICMP6]) -> Munch:
        # TODO: Extract more data from ICMPv6 and ICMP packets
        data = Munch()
        try:
            data.icmp_type = packet.type
            data.icmp_code = packet.code

            data['icmp_message'] = self.get_icmp_message(
                icmp_type_data=self._get_icmp_types_data(packet),
                icmp_type=packet.type,
                icmp_code=packet.code
            )
        except BaseException as ex:
            logging.warning('Unable to extract ICMP from `%s`. Error: `%s`', type(packet), ex)
            raise ex

        return data

    def _get_icmp_types_data(self, packet: Union[ICMP, ICMP6]) -> dict:
        if isinstance(packet, ICMP6):
            return ICMP6_TYPES

        return ICMP_TYPES

    def get_icmp_message(self, icmp_type_data: dict, icmp_type: int, icmp_code: int) -> Union[str, int]:
        type_data = icmp_type_data.get(icmp_type, '')
        if isinstance(type_data, dict):
            if self.config.use_numeric_values is True:
                return icmp_code
            return type_data.get(icmp_code, '')

        if self.config.use_numeric_values is True:
            return icmp_type

        return type_data


class Icmp6PacketParser(BaseIcmpPacketParser):
    def __init__(self, *args, config: ConfigurationData, **kwargs):
        super(Icmp6PacketParser, self).__init__(config, *args, **kwargs)

    def extract_data(self, packet: ICMP6) -> dict:
        return super(Icmp6PacketParser, self).extract_data(packet)


class IcmpPacketParser(BaseIcmpPacketParser):
    def __init__(self, *args, config: ConfigurationData, **kwargs):
        super(IcmpPacketParser, self).__init__(config, *args, **kwargs)

    def extract_data(self, packet: ICMP) -> Munch:
        return super(IcmpPacketParser, self).extract_data(packet)
