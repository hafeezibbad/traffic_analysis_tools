from abc import ABC

from munch import Munch


class PacketParserInterface(ABC):
    @staticmethod
    def extract_data(packet) -> Munch:
        pass
