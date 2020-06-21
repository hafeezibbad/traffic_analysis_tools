import gc
import os
import sys
import logging
import time


sys.path.append(os.getcwd())

from typing import Optional, Union, Dict, Any, Tuple

import click

from munch import Munch

from core.analyzer.pcap_processor import PcapProcessor
from core.configuration.data import ConfigurationData
from core.configuration.manager import ConfigurationManager
from core.errors.generic_errors import GenericError
from core.lib.common import write_json_to_file
from core.lib.file_utils import list_files_in_directory, get_filename_and_ext, remove_file
from core.models.pcap_file_info import PcapFileInfo
from core.static.utils import StaticData


def configure_logging(log_file_path: str = None, verbose: bool = False):
    logging_args = dict(format='%(asctime)s - %(name)s %(levelname)s - %(message)s')
    if log_file_path is not None:
        logging_args['filename'] = log_file_path
        logging_args['filemode'] = 'w'

    if verbose is True:
        logging_args['level'] = logging.DEBUG
    else:
        logging_args['level'] = logging.INFO

    logging.basicConfig(**logging_args)


def load_configuration(config_file_path: str = None) -> Optional[ConfigurationData]:
    config_manager = ConfigurationManager()
    config = config_manager.load_data_from_configuration_file(config_file_path)

    return config


def get_results_file_path(
        pcap_file_path: str = '',
        source_directory: str = '',
        output_directory: str = '',
        suffix: str = 'data'
) -> str:
    filename, ext = get_filename_and_ext(pcap_file_path)
    results_file_name = os.path.basename(pcap_file_path)[:-len(ext)-1] + '_{}.csv'.format(suffix)
    sub_directory_path = os.path.dirname(pcap_file_path).replace(source_directory + '/', '')
    results_file_path = os.path.join(output_directory, sub_directory_path, results_file_name)

    return results_file_path


def process_pcap(
        pcap_processor: PcapProcessor,
        pcap_file: str = '',
        results_file_path: str = '',
        overwrite_results: bool = True
) -> Tuple[Optional[PcapFileInfo], float]:
    gc.collect()    # Force garbage collection to minimize memory collection
    if os.path.exists(pcap_file or '') is False:
        logging.error('Invalid pcap file path specified: `%s`', pcap_file)

    if os.path.exists(results_file_path) is True and overwrite_results is False:
        logging.info('Results file already exist at path: `%s`. skipping because overwrite is `%s`',
                     results_file_path, overwrite_results)
        return None, 0

    logging.info('Starting to process pcap file: `%s`', pcap_file)

    st = time.time()

    try:
        pcap_summary = pcap_processor.process(input_file=pcap_file, output_file=results_file_path)

    except GenericError as ex:
        logging.error(ex.message)
        return None, 0

    processing_time = time.time() - st

    logging.info('Processed `%s` in `%s` seconds', pcap_file, processing_time)

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
        try:
            result_file_path = get_results_file_path(
                pcap_file_path=pcap_file,
                source_directory=source_directory,
                output_directory=output_directory,
                suffix=results_file_suffix
            )
            pcap_summary, processing_time = process_pcap(
                pcap_processor=pcap_processor,
                pcap_file=pcap_file,
                results_file_path=result_file_path,
                overwrite_results=overwrite_results
            )
            if pcap_summary is None:
                continue

            summary_data = get_summary_for_pcap_processor(pcap_summary, processing_time)
            logging.debug('Summary data from pcap file: `%s`', summary_data)
            summary_results['items'].append(summary_data)

            if remove_original is True:
                logging.info('Removing source pcap file at `%s`', pcap_file)
                remove_file(pcap_file)

        except Exception as ex:
            logging.error('Error processing pcap file: `%s`. Error `%s`', pcap_file, ex)

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
@click.option('--overwrite', is_flag=True, default=False,
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
