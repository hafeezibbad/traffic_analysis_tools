import logging
from typing import Tuple

from dpkt.ip import IP
from dpkt.ip6 import IP6
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.parser.base import PacketParserInterface
from core.lib.ip_utils import IpAddrUtils


class Ip6PacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_utils = IpAddrUtils()

    def extract_data(self, packet: IP6) -> Munch:
        data = Munch()
        try:
            data.src_ip, data.dst_ip = self.extract_src_dest_ip(packet)
            data.ip_proto = packet.p
            data.ip_payload_size = len(packet.data)
            if packet.all_extension_headers:
                data.ip6_nxt_hdr = self.config.FieldDelimiter.join(
                    [str(header.nxt) for header in packet.all_extension_headers]
                )

        except BaseException as ex:
            logging.warning('Unable to extract IP6 from `{}`.Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def extract_src_dest_ip(self, ip_packet: IP) -> Tuple:
        src_ip = self.ip_utils.inet_to_str(ip_packet.src)
        dst_ip = self.ip_utils.inet_to_str(ip_packet.dst)

        if self.config.use_numeric_values is True:
            return self.ip_utils.ip_to_int(src_ip), self.ip_utils.ip_to_int(dst_ip)

        return src_ip, dst_ip
