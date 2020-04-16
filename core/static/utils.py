import logging
import socket
from typing import Optional

from munch import Munch, DefaultMunch

from core.errors import FileError
from core.file_processor.json_file import JsonFileProcessor
from core.lib.manuf_file import load_manuf_file
from core.static.CONSTANTS import IP_PROTOCOLS_DATA_FILE_PATH, LAYER4_PORTS_DATA_FILE_PATH, TCP_FLAGS_DATA_FILE_PATH, \
    MANUF_DATA_FILE_PATH, ETHER_TYPES_DATA_FILE_PATH, IP_OPTIONS_DATA_FILE_PATH


class StaticData:
    @staticmethod
    def load_manuf_data(file_path: str = MANUF_DATA_FILE_PATH) -> Optional[Munch]:
        manuf_data = load_manuf_file(manuf_file_path=file_path)
        if manuf_data is None:
            return None

        return DefaultMunch(None, manuf_data)

    @staticmethod
    def load_ip_protocols_data(file_path: str = IP_PROTOCOLS_DATA_FILE_PATH) -> Optional[Munch]:
        return JsonFileProcessor().read(file_path)

    @staticmethod
    def load_ip_options_data(file_path: str = IP_OPTIONS_DATA_FILE_PATH) -> Optional[Munch]:
        return JsonFileProcessor().read(file_path)

    @staticmethod
    def load_layer4_ports_data(file_path: str = LAYER4_PORTS_DATA_FILE_PATH) -> Optional[Munch]:
        return JsonFileProcessor().read(file_path)

    @staticmethod
    def load_tcp_flag_data(file_path: str = TCP_FLAGS_DATA_FILE_PATH) -> Optional[Munch]:
        return StaticData.__load_data_from_json_file(file_path)

    @staticmethod
    def load_ether_types_data(file_path: str = ETHER_TYPES_DATA_FILE_PATH) -> Optional[Munch]:
        return StaticData.__load_data_from_json_file(file_path)

    @staticmethod
    def __load_data_from_json_file(file_path: str = None) -> Optional[Munch]:
        try:
            return JsonFileProcessor().read(file_path)

        except FileError:
            logging.error('Loading data from path: {} failed'.format(file_path))

        return None

    @staticmethod
    def __load_ip_proto_mapping() -> dict:
        ip_protocol_table = dict()
        try:
            for name, num in vars(socket).items():
                if name.startswith("IPPROTO"):
                    ip_protocol_table[num] = name[8:]

        except Exception as ex:
            logging.error('Unable to protocol number to name mapping. Error: {}'.format(ex))

        return ip_protocol_table
