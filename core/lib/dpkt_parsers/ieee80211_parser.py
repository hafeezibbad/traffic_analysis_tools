import logging
from datetime import datetime

from dpkt.ah import AH
from dpkt.ieee80211 import IEEE80211
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.models.packet_data import PacketData


class IEEE80211PacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def extract_data(self, packet: IEEE80211) -> Munch:
        data = Munch()
        # TODO: Improve the data collection for this packet e.g. Extract key information
        try:
            data.ieee80211_version = packet.version
            data.ieee80211_payload_size = len(packet.data)

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(packet), ex))

        return data
