import os
from pathlib import Path

from core.lib.file_utils import recursive_listdir

# TODO: Use Path objects
SCRIPTS_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
print(SCRIPTS_DIR_PATH)
PROJECT_DIR_PATH = os.path.dirname(SCRIPTS_DIR_PATH)
CONFIG_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'configs')
LOG_FILE_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'logs')
FIXTURES_DIR_PATH = os.path.join(PROJECT_DIR_PATH, 'fixtures')
PCAP_DIR_PATH = os.path.join(FIXTURES_DIR_PATH, 'pcap_files')
RESULTS_DIR_PATH = os.path.join(FIXTURES_DIR_PATH, 'results')

pcap_files = recursive_listdir(directory=str(PCAP_DIR_PATH), extension='pcap_files')
TEST_PCAP_FILE_PATH = os.path.join(PCAP_DIR_PATH, 'eyeplus-babycam1-eth0-30min-capture-14.pcap_files')
