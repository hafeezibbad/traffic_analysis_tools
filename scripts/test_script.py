#!/usr/bin/python

import os
import sys

sys.path.append(os.getcwd())

from core.analyzer.pcap_processor import PcapProcessor
from core.configuration.manager import ConfigurationManager
from scripts.common import RESULTS_DIR_PATH, CONFIG_DIR_PATH, PCAP_DIR_PATH, PROJECT_DIR_PATH

config_manager = ConfigurationManager()
config = config_manager.load_data_from_configuration_file(file_path=os.path.join(CONFIG_DIR_PATH, 'config.yml'))
config.p0f_wd = os.path.join(PROJECT_DIR_PATH, config.p0f_wd)
pcap_processor = PcapProcessor(config=config)

# Read and process the file
trace_info, status = pcap_processor.process(
    input_file=os.path.join(PCAP_DIR_PATH, 'dcs-942l-eth0-30min-capture-30.pcap'),
    # input_file=os.path.join(PCAP_DIR_PATH, 'ssdp_packets.pcap'),
    output_file=os.path.join(RESULTS_DIR_PATH, 'results.csv')
)

print(trace_info.get_summary(output_format='json'))
