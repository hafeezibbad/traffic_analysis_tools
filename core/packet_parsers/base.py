from abc import ABC

from munch import Munch

from core.models.packet_data import PacketData


class PacketParserInterface(ABC):
    @staticmethod
    def extract_data(packet) -> Munch:
        pass
