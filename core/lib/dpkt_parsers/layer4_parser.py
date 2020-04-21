import logging
from typing import Tuple, Optional, Union

import dpkt
from dpkt.tcp import TCP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.models.packet_data import PacketData
from core.static.CONSTANTS import LAYER4_PROTOCOLS
from core.static.utils import StaticData


class Layer4PacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None, *args, **kwargs):
        self.config = config
        self.static_data = static_data or StaticData()

    def extract_data(self, packet) -> Munch:
        raise NotImplementedError

    def extract_common_data(self, protocol_type: str, packet: Union[UDP, TCP]) -> Munch:
        data = Munch()
        try:
            data.layer4_payload_size = len(packet.data)
            data.src_port, data.dst_port = self.extract_src_dest_port(packet)
            data.outgoing = self.is_packet_outgoing(packet)
            data.layer7_proto = self.get_layer7_proto_number(packet)
            data.layer7_proto_name = self.get_protocol_info_from_port(
                port_number=data.layer7_proto, protocol_type=protocol_type
            )

        except BaseException as ex:
            logging.warning('Unable to extract Layer4 from `{}`. Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def is_packet_outgoing(self, packet: Union[UDP, TCP]) -> bool:
        # FIXME: This can be improved?
        if 10000 <= packet.sport < 65536:     # Lower limit from static/layer4_port_data.json
            return True

        return False

    def extract_src_dest_port(self, packet: Union[UDP, TCP]) -> Tuple:
        return packet.sport, packet.dport

    def get_layer7_proto_number(self, packet: Union[UDP, TCP]) -> Optional[int]:
        if packet is None:
            return None

        if self.is_packet_outgoing(packet):
            return packet.dport

        return packet.sport

    def get_protocol_info_from_port(self, port_number: int, protocol_type: str) -> Optional[str]:
        # FIXME: Check if we need to find protocol abbrv for source port as well
        port_number = str(port_number)
        protocol_data = self.static_data.layer4_ports_data.get(port_number)
        if protocol_data is None:
            return None

        protocol_abbrv, protocol_desc = self.get_protocol_info_from_protocol_data(protocol_data, protocol_type)
        return protocol_abbrv or protocol_desc

    def get_protocol_info_from_protocol_data(self, data: dict, protocol_type: str) -> Tuple:
        protocol_abbrv = []
        protocol_description = []

        if isinstance(data, list):
            for item in data:
                _abbrv, _desc = self.extract_protocol_info_from_protocol_data(item, protocol_type)
                if _abbrv is not None:
                    protocol_abbrv.append(_abbrv)
                if _desc is not None:
                    protocol_description.append(_desc)

        elif isinstance(data, dict):
            _abbrv, _desc = self.extract_protocol_info_from_protocol_data(data, protocol_type)
            protocol_abbrv.append(_abbrv)
            protocol_description.append(_desc)

        else:
            # Unexpected (invalid) data type
            return None, None

        return self.config.FieldDelimiter.join([abbrv for abbrv in protocol_abbrv if abbrv]), \
            self.config.FieldDelimiter.join([desc for desc in protocol_description if desc])

    def extract_protocol_info_from_protocol_data(self, data: dict, protocol_type: str) -> Tuple:
        protocol_abbrv = ''
        protocol_description = ''

        if protocol_type in LAYER4_PROTOCOLS and data[protocol_type] is True:
            protocol_abbrv = data.get('abbrv')
            protocol_description = data.get('description')

        return protocol_abbrv.replace(',', self.config.FieldDelimiter), \
               protocol_description.replace(',', self.config.FieldDelimiter)


class TcpPacketParser(Layer4PacketParser):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None,  *args, **kwargs):
        super(TcpPacketParser, self).__init__(config, static_data, *args, **kwargs)

    def extract_data(self, packet: TCP) -> Munch:
        tcp_packet_data = Munch()
        tcp_packet_data.update(self.extract_common_data(protocol_type='tcp', packet=packet))
        tcp_packet_data.update(self.extract_flags(packet))

        return tcp_packet_data

    def extract_flags(self, packet: TCP) -> Munch:
        flags = Munch()

        flags.tcp_fin_flag = (packet.flags & dpkt.tcp.TH_FIN) != 0
        flags.tcp_syn_flag = (packet.flags & dpkt.tcp.TH_SYN) != 0
        flags.tcp_rst_flag = (packet.flags & dpkt.tcp.TH_RST) != 0
        flags.tcp_psh_flag = (packet.flags & dpkt.tcp.TH_PUSH) != 0
        flags.tcp_ack_flag = (packet.flags & dpkt.tcp.TH_ACK) != 0
        flags.tcp_urg_flag = (packet.flags & dpkt.tcp.TH_URG) != 0
        flags.tcp_ece_flag = (packet.flags & dpkt.tcp.TH_ECE) != 0
        flags.tcp_cwr_flag = (packet.flags & dpkt.tcp.TH_CWR) != 0

        return flags


class UDPPacketParser(Layer4PacketParser):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None, *args, **kwargs):
        super(UDPPacketParser, self).__init__(config, static_data, *args, **kwargs)

    def extract_data(self, packet: Union[UDP, TCP]) -> Munch:
        print(type(packet))
        print(packet)
        print(packet.data)
        print('-' * 80)
        return self.extract_common_data(protocol_type='udp', packet=packet)
