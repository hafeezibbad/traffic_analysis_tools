import gc
import os
import sys
import logging
import time

sys.path.append(os.getcwd())

from typing import Optional, Union, Dict, Any, Tuple

import click

from munch import Munch
from pip.utils import logging

from core.analyzer.pcap_processor import PcapProcessor
from core.configuration.data import ConfigurationData
from core.configuration.manager import ConfigurationManager
from core.lib.common import write_json_to_file
from core.lib.file_utils import list_files_in_directory, get_filename_and_ext, remove_file
from core.lib.logging_utils import setup_logging
from core.models.pcap_file_info import PcapFileInfo
from core.static.utils import StaticData


def configure_logging(log_file_path: str = None, verbose: bool = False):
    log_file_path = log_file_path or 'process-pcap-files.log'
    _dirname = os.path.dirname(log_file_path) or os.getcwd()
    _filename = os.path.basename(log_file_path)

    logger = setup_logging(
        name=__name__,
        log_directory=_dirname,
        file_name=_filename
    )

    if verbose is True:
        logger.setLevel('DEBUG')


def load_configuration(config_file_path: str = None) -> Optional[ConfigurationData]:
    config_manager = ConfigurationManager()
    config = config_manager.load_data_from_configuration_file(config_file_path)

    return config


def get_results_file_path(
        pcap_file_path: str = '',
        output_directory: str = '',
        suffix: str = 'data'
) -> str:
    filename, ext = get_filename_and_ext(pcap_file_path)
    results_file_name = os.path.basename(pcap_file_path)[:-len(ext)+1] + '_{}.csv'.format(suffix)
    results_file_path = os.path.join(output_directory, results_file_name)

    return results_file_path


def process_pcap(
        pcap_processor: PcapProcessor,
        pcap_file: str = '',
        results_file_path: str = '',
        overwrite_results: bool = True
) -> Tuple[Optional[Union[Munch, dict]], float]:
    gc.collect()    # Force garbage collection to minimize memory collection
    if os.path.exists(pcap_file or ''):
        logging.error('Invalid pcap file path specified: `{}`'.format(pcap_file))
        exit(-1)

    if os.path.exists(results_file_path) is True and overwrite_results is False:
        logging.error('Results file already exist at path: `{}`'.format(results_file_path))
        exit(-1)

    logging.debug('Starting to process pcap file: `{}`'.format(pcap_file))

    st = time.time()
    pcap_summary = pcap_processor.process(input_file=pcap_file, output_file=results_file_path)
    processing_time = time.time() - st

    logging.info('Processed `{}` in `{}` seconds'.format(pcap_file, processing_time))

    return pcap_summary, processing_time


def get_summary_for_pcap_processor(
        pcap_summary: PcapFileInfo = None,
        processing_time: float = 0.0
) -> Union[Munch, Dict[str, Any]]:
    if not pcap_summary:
        return {}

    summary_data = pcap_summary.get_summary(output_format='json')
    summary_data['identifier'] = os.path.basename(summary_data.get('file_name', '').strip().split('.')[0])
    summary_data['processing_time'] = str(processing_time)

    return summary_data


def process_pcap_files(
        pcap_processor: PcapProcessor,
        source_directory: str,
        output_directory: str,
        remove_original: bool = False,
        overwrite_results: bool = True,
        results_file_suffix: str = 'data'
) -> Union[Munch, dict]:
    # Get all source files
    pcap_files = list_files_in_directory(source_directory, extensions=['pcap'], recursive=True)

    summary_results = dict(items=[])
    for pcap_file in pcap_files:
        result_file_path = get_results_file_path(
            pcap_file_path=pcap_file,
            output_directory=output_directory,
            suffix=results_file_suffix
        )
        pcap_summary, processing_time = process_pcap(
            pcap_processor=pcap_processor,
            pcap_file=pcap_file,
            results_file_path=result_file_path,
            overwrite_results=overwrite_results
        )
        summary_data = get_summary_for_pcap_processor(pcap_summary, processing_time)
        logging.debug(summary_data)
        summary_results['items'].append(summary_data)

        if remove_original is True:
            logging.info('Removing source pcap file at `{}`'.format(pcap_file))
            remove_file(pcap_file)

    return summary_results


@click.command()
@click.option('-c', '--config-file-path', required=True, type=str, help='Path to configuration file')
@click.option('-s', '--source-directory', required=True, type=str,
              help='Path to directory containing pcap files which should be processed')
@click.option('-o', '--output-directory', required=True, default=os.getcwd(), type=str,
              help='Path to directory where output should be written. Default: PWD')
@click.option('-l', '--log-file-path', default='', type=str,
              help='Path to store log file. If only filename is provided, it will be stored in PWD')
@click.option('--output-suffix', default='data', type=str, help='Suffix added to processed file')
@click.option('--remove-original', is_flag=True, default=False, help="Remove source pcap file after processing")
@click.option('--overwrite', is_flag=True, default=True,
              help="Overwrite result files if they already exist in output folder.")
@click.option('-v', '--verbose', is_flag=True, default=False, help="Print debug logs")
def process(
        config_file_path,
        source_directory,
        output_directory,
        log_file_path,
        output_suffix,
        remove_original,
        overwrite,
        verbose
):
    print(config_file_path, source_directory, output_directory, verbose)
    exit(1)
    # configure logging
    configure_logging(log_file_path=log_file_path, verbose=verbose)

    # load configuration
    config = load_configuration(config_file_path=config_file_path)

    pcap_processor = PcapProcessor(config=config, static_data=StaticData())

    # process files
    summary_results = process_pcap_files(
        pcap_processor=pcap_processor,
        source_directory=source_directory,
        output_directory=output_directory,
        remove_original=remove_original,
        overwrite_results=overwrite,
        results_file_suffix=output_suffix
    )

    # Write results to a file
    write_json_to_file(
        data=summary_results,
        file_path=os.path.join(output_directory, 'summary_results.json')
    )


if __name__ == '__main__':
    process()
