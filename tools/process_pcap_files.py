#!/usr/bin/python
"""
This scripts takes the path to directory and searches for PCAP files in that directory recursively. After that,
it processes all pcap files to extract the data in form of a csv file. These CSV files are saved at path specific in
results directory.
"""
import gc
import os
import sys
import time

sys.path.append(os.getcwd())

# pylint: disable=wrong-import-position
from core.lib.logging_utils import setup_logging  # noqa
from core.analyzer.pcap_processor import PcapProcessor  # noqa
from core.configuration.manager import ConfigurationManager  # noqa
from core.lib.common import print_json, write_json_to_file  # noqa
from core.lib.file_utils import list_files_in_directory, get_filename_and_ext  # noqa
from core.static.utils import StaticData  # noqa
from tools.common import RESULTS_DIR_PATH, CONFIG_DIR_PATH, PCAP_DIR_PATH, LOG_FILE_DIR_PATH  # noqa

logger = setup_logging(
    name=__name__,
    log_directory=LOG_FILE_DIR_PATH,
    file_name='pcap_processor_log'
)

config_manager = ConfigurationManager()
config = config_manager.load_data_from_configuration_file(file_path=os.path.join(CONFIG_DIR_PATH, 'config.yml'))
stdout_file = os.path.join(RESULTS_DIR_PATH, 'prog_stdout.json')
# Get list of PCAP files
pcap_files = list_files_in_directory(directory=PCAP_DIR_PATH, extensions='pcap', recursive=True)
static_data = StaticData()
pcap_processor = PcapProcessor(config=config, static_data=static_data)

summary_stats_pcap = dict(items=[])
OVERWRITE_OLD_RESULTS = True
for pcap_file in pcap_files:
    gc.collect()
    file_name, ext = get_filename_and_ext(pcap_file)
    result_file_path = pcap_file.replace(PCAP_DIR_PATH, RESULTS_DIR_PATH)[:-(len(ext)+1)] + '_data.csv'
    if os.path.exists(result_file_path) and OVERWRITE_OLD_RESULTS is False:
        continue
    st = time.time()
    print('Start processing file: {}'.format(pcap_file))
    # Read and process the file
    pcap_summary, status = pcap_processor.process(
        input_file=pcap_file,
        output_file=result_file_path
    )
    summary_data = pcap_summary.get_summary(output_format='json')
    summary_data['identifier'] = os.path.basename(summary_data.get('file_name', '').strip().split('.')[0])
    summary_data['processing_time'] = str(time.time() - st)
    summary_stats_pcap['items'].append(summary_data)
    print('Processed: {} in {} seconds'.format(pcap_file, summary_data['processing_time']))
    print_json(data=summary_data)

# Summary results for all processed files are stored in RESULTS_DIR/summary.json
write_json_to_file(
    data=summary_stats_pcap,
    file_path=os.path.join(RESULTS_DIR_PATH, 'summary.json')
)
