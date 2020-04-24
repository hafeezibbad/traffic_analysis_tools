from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.dpkt_parsers.natpmp import NatPmp


class NatPmpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def extract_data(self, nat_pmp_packet: NatPmp) -> Munch:
        data = Munch()

        return data
