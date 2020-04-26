from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.dpkt_parsers.natpmp import Natpmp
from core.lib.ip_utils import IpAddrUtils


class NatpmpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config
        self.ip_addr_utils = IpAddrUtils()

    def extract_data(self, natpmp_packet: Natpmp) -> Munch:
        data = Munch()

        data.natpmp_version = natpmp_packet.version
        data.natpmp_opcode = natpmp_packet.opcode
        data.natpmp_reserved = natpmp_packet.reserved
        data.natpmp_result = natpmp_packet.result
        data.natpmp_sssoe = natpmp_packet.sssoe
        data.natpmp_lifetime = natpmp_packet.lifetime
        data.natpmp_internal_port = natpmp_packet.internal_port
        data.natpmp_external_port = natpmp_packet.external_port
        if natpmp_packet.external_ip != -1:
            # There is an NatPMP External Address Response packet so extract external IP address
            if self.config.use_numeric_values is False:
                data.natpmp_external_ip = natpmp_packet.external_ip
            else:
                data.natpmp_external_ip = self.ip_addr_utils.int_to_ip(natpmp_packet.external_ip)

        return data
