import logging
import os
from pathlib import Path
from typing import Tuple, TextIO, Any

import dpkt

from core.analyzer.base_processor import BaseProcessor
from core.configuration.data import ConfigurationData
from core.errors.generic_errors import GenericError
from core.file_processor.base import FileProcessorBase
from core.file_processor.errors import FileError, FileErrorType
from core.lib.dpkt_utils import DpktUtils
from core.lib.file_utils import check_valid_path
from core.models.packet_data import PacketData
from core.models.pcap_file_info import PcapFileInfo
from core.static.utils import StaticData


class PcapProcessor(BaseProcessor):
    def __init__(self, config: ConfigurationData, static_data: StaticData = None) -> None:
        """PCAP processor class contains functionality for processing and analyzing PCAP files.

        Parameters
        ----------
        config: ConfigurationData
            Application configuration data
        static_data: StaticData
            Static data which is used in analyzing PCAP files. This data contains protocol numbers, port numbers to
            description mappings.
        """
        self.pcap_file_info = PcapFileInfo()
        self.config = config
        self.static_data = static_data
        if self.static_data is None or not isinstance(self.static_data, StaticData):
            self.static_data = StaticData()
        self.dpkt_utils = DpktUtils(config=config, static_data=static_data)

    # pylint: disable=arguments-differ
    def process(
            self,
            input_file: str = None,
            output_file: str = None,
            pcap_filter: str = ''
    ) -> PcapFileInfo:
        """Process a .pcap file by reading each packet, extract basic statistics from the packet, writes
        these statistics to an output csv file.

        Parameters
        -----------
        input_file: str
            Path to input pcap_files file which needs to be processed
        output_file: str
            Path to output file where results should be written
        pcap_filter: str, optional
            Set up a pypcap's BRF expression to filter packets read from PCAP file. For example, to only process DNS
            packets use pcap_filter='udp dst port 53'.

        Returns
        --------
        pcap_file_info: PcapFileInfo
            JSON object containing summary information about data extracted from PCAP file

        Raises
        -------
        FileError: Exception
            If there is some issue with reading or processing input pcap file, or writing data to output csv file.
        """
        logging.debug('input_file: %s', input_file)

        pcap_file, captures = self.load_pcap_file_for_reading(input_file, pcap_filter)
        pcap_file_info = PcapFileInfo()
        if pcap_file is None:
            return pcap_file_info

        result_file = self.open_output_file_and_write_headers(output_file)

        initial_ts = 0
        count = 0
        total_data = 0
        try:
            for ts, buff in captures:
                if initial_ts == 0:
                    initial_ts = ts
                pcap_file_info.stop_time = ts
                try:
                    count += 1
                    total_data += len(buff)

                    packet_data = self.extract_stats_from_packet(ts=ts, packet=buff, initial_timestamp=initial_ts)
                    if packet_data is None:
                        pass
                    result_file.write(packet_data.to_csv_string(delimiter=self.config.ResultFileDelimiter) + '\n')

                except Exception as ex:
                    logging.error('Unable to process packate at ts: `%s`. Error `%s`'.format(ts, ex))

        except Exception as ex:
            raise GenericError(message='Unable to process pcap file `%s`. Error `%s`'.format(pcap_file, ex)) from ex

        logging.info('%s packets processed from %s', count, input_file)
        pcap_file.close()
        result_file.close()

        pcap_file_info.file_name = input_file
        pcap_file_info.results_file_name = output_file
        pcap_file_info.start_time = initial_ts
        pcap_file_info.packet_count = count
        pcap_file_info.total_data = total_data

        return pcap_file_info

    def open_output_file_and_write_headers(self, output_file_path: str) -> TextIO:
        """Create file for writing data extracted from packet, and write headers.

        Parameters
        ----------
        output_file_path: str
            Path to output file to writen data

        Returns
        --------
        output_file: TextIO
            File object for writing output data
        """
        if not os.path.exists(os.path.dirname(output_file_path)):
            Path(os.path.dirname(output_file_path)).mkdir(parents=True, exist_ok=True)

        output_file = FileProcessorBase.open_file(output_file_path, mode='w')  # Overwrites old file
        output_file.write(PacketData.packet_data_file_headers(delimiter=self.config.ResultFileDelimiter) + '\n')

        return output_file

    def load_pcap_file_for_reading(self, file_path: str, pcap_filter: str = '') -> Tuple[TextIO, Any]:
        """Open pcap file for reading from specified file path.

        Parameters
        ----------
        file_path : str
            Path to pcap file
        pcap_filter : str, optional
            Set up a pypcap's BRF expression to filter packets read from PCAP file. For example, to only process DNS
            packets use pcap_filter='udp dst port 53'.

        Returns
        -------
        file_object: TextIO
            File object with open pcap file for reading
        captures: Any
            dpkt pcap reader object

        Raises
        ------
        FileError: Exception
            Raised if input pcap file can not be read.
        """
        if check_valid_path(file_path, valid_extensions=['pcap']) is False:
            raise FileError(
                message='Invalid file path ({}) specified for pcap file'.format(file_path),
                error_type=FileErrorType.INVALID_FILE_PATH
            )
        try:
            pcap_file = FileProcessorBase.open_file(file_path, mode='rb')
            captures = dpkt.pcap.Reader(pcap_file)
            if pcap_filter:
                captures.setfilter(pcap_filter)           # pypcap's BRF expression

            return pcap_file, captures

        except Exception as ex:
            raise FileError(
                message='Unable to load pcap_files file to dpkt. Error: {}'.format(ex),
                error_type=FileErrorType.UNSPECIFIED_ERROR
            ) from ex

    def get_timestamp_of_first_packet_in_pcap_file(self, file_path: str, pcap_filter: str = '') -> float:
        first_ts = -1
        file_obj, captures = self.load_pcap_file_for_reading(file_path, pcap_filter)
        for ts, buff in captures:
            first_ts = ts
            break

        file_obj.close()             # Close the file

        return first_ts

    def extract_stats_from_packet(self, ts, packet, initial_timestamp: float) -> PacketData:
        packet_data = PacketData()

        packet_data.timestamp = ts
        packet_data.ref_time = ts - initial_timestamp
        packet_data.size = len(packet)
        try:
            # Handle Layer 2: Ethernet
            try:
                eth = dpkt.ethernet.Ethernet(packet)

            except IndexError:
                # This is a Malformed data, experienced in Apple deviecs. Since rest of packet is malformed,
                # we only extract source, destination MAC address and IP protocol
                data = self.dpkt_utils.parse_byte_data_as_ethernet_headers(packet)

                packet_data.src_mac = data.src_mac
                packet_data.dst_mac = data.dst_mac
                packet_data.eth_type = data.eth_type
                packet_data.eth_payload_size = data.payload_size

                return packet_data

            packet_data = self.dpkt_utils.extract_data_from_eth_frame(
                eth_frame=eth,
                packet_data=packet_data
            )
            # Skip further processing for packets which do not have layer 4 data
            if eth.type in [
                    dpkt.ethernet.ETH_TYPE_ARP,
                    6,  # IEEE 802.1 Link Layer Control
                    34958,  # IEEE 802.1X Authentication
                    35085  # TDLS Discovery request
            ]:
                return packet_data

            # Handle Layer 3: IP, IGMP, ARP, LLC
            layer3_packet = self.dpkt_utils.load_layer3_packet(eth)
            if layer3_packet is None:
                return packet_data

            packet_data = self.dpkt_utils.extract_data_from_layer3_packet(layer3_packet, packet_data=packet_data)

            # Handler Layer 4: TCP, UDP, ICMP
            layer4_packet = self.dpkt_utils.load_layer4_packet(layer3_packet)
            if layer4_packet is None:
                logging.warning('Unable to extract data from layer3 packet')
                return packet_data

            packet_data = self.dpkt_utils.extract_data_from_layer4_packet(layer4_packet, packet_data)
            if packet_data.tcp_syn_flag is True and packet_data.tcp_ack_flag is False:
                packet_data = self.dpkt_utils.extract_tcp_syn_signature(eth.data, packet_data)

            # Handler Layer 7: DNS, UPnP, DHCP, mDNS, NTP
            layer7_packet = self.dpkt_utils.load_layer7_packet(layer4_packet, packet_data)
            if layer7_packet is None:
                logging.debug(
                    'Unable to extract layer7 packet with src port `%s`, dst port `%s`',
                    packet_data.src_port,
                    packet_data.dst_port
                )
            packet_data = self.dpkt_utils.extract_data_from_layer7_packet(layer7_packet, packet_data)

        except Exception as ex:
            logging.error('Error in processing packet at ref_time: `%s`. Error: `%s`',
                          packet_data.ref_time, ex)

        return packet_data
