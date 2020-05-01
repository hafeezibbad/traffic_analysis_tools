import json
import os

from core.lib.numpy_utils import NpEncoder

# TODO: Use Pathlib.Path objects
SCRIPTS_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR_PATH = os.path.dirname(SCRIPTS_DIR_PATH)
CONFIG_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'configs')
LOG_FILE_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'logs')
FIXTURES_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'fixtures')
PCAP_DIR_PATH = os.path.join(FIXTURES_DIR_PATH, 'pcap_files')
RESULTS_DIR_PATH = os.path.join(FIXTURES_DIR_PATH, 'results')


def print_as_json(data, indent=2, sort_keys=False) -> None:
    print(json.dumps(data, indent=indent, sort_keys=sort_keys, cls=NpEncoder))
