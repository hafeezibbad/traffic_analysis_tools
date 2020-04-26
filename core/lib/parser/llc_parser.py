from dpkt.llc import LLC
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.parser.base import PacketParserInterface


class LlcPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def extract_data(self, llc_packet: LLC) -> Munch:
        data = Munch()
        # TODO: Implement
        return data
