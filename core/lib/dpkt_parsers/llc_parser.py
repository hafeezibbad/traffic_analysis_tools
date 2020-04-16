from dpkt.llc import LLC
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface


class LlcPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def extract_data(self, packet: LLC) -> Munch:
        data = Munch()
        # TODO: Implement
        return data
