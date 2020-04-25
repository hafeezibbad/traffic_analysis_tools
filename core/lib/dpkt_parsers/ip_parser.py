import logging
from typing import Tuple, Optional, Union

import binascii
import dpkt
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils
from core.static.utils import StaticData


class IpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None):
        self.config = config
        self.ip_utils = IpAddrUtils()
        self.static_data = static_data or StaticData()

    @staticmethod
    def load_ip_packet_from_ethernet_frame(packet_data: bytes) -> Union[IP, IP6]:
        if isinstance(packet_data, IP) or isinstance(packet_data, IP6):
            return packet_data

        # Packet data is bytes because it is a fragmented packet.
        try:
                return IP(packet_data)

        except dpkt.dpkt.UnpackError:
            return IP6(packet_data)  # When IPv6 packet is encapsulated in IPv4 packet

        except BaseException as ex:
            logging.error('Can not parse Ethernet frame as IPv4 or IPv6 packet. Error: {}'.format(ex))
            raise ex

    def extract_data(self, packet: IP) -> Munch:
        data = Munch()
        try:
            data.src_ip, data.dst_ip = self.extract_src_dest_ip(packet)
            data.ip_proto = self.get_ip_proto_name(packet.p)
            data.ip_payload_size = len(packet.data)
            data.ip_ttl = packet.ttl
            data.ip_tos = packet.tos
            data.ip_do_not_fragment = bool(packet.off & dpkt.ip.IP_DF)
            data.ip_more_fragment = bool(packet.off & dpkt.ip.IP_MF)
            data.ip_opts = self.parse_ip_options(packet.opts) or ''

        except BaseException as ex:
            logging.warning('Unable to extract IP4 from `{}`.Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def extract_src_dest_ip(self, ip_packet: IP) -> Tuple:
        return self.ip_utils.inet_to_str(ip_packet.src), self.ip_utils.inet_to_str(ip_packet.dst)

    def parse_ip_options(self, ip_options: bytes) -> str:
        # Split 4 bytes \x94\x04\x00\x00 to single bytes [94, 04, 00, 00]
        options = binascii.hexlify(ip_options).decode('utf-8')
        if not options:
            return ''

        options = [options[i:i+2] for i in range(0, len(options), 2)]
        # first byte gives information of IP options
        hex_option = '0x' + options[0]

        return self.static_data.ip_options_data.get(hex_option, {}).get('abbrv') or hex_option

    def get_ip_proto_name(self, proto_num: int) -> str:
        try:
            proto_key = str(proto_num)
        except ValueError:
            return proto_num

        proto_name = ''
        if proto_key in self.static_data.ip_protocol_data:
            proto_name = self.static_data.ip_protocol_data.get(proto_key, {}).get('keyword', '')

        return proto_name or proto_key
