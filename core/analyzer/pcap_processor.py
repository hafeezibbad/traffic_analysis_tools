import logging
import os
import traceback
from pathlib import Path
from typing import Tuple

import dpkt

from core.analyzer.base_processor import BaseProcessor
from core.configuration.data import ConfigurationData
from core.errors import FileError, FileErrorTypes
from core.lib.common import print_json
from core.lib.dpkt_utils import DpktUtils
from core.models.packet_data import PacketData
from core.models.pcap_file_info import PcapFileInfo
from core.static.utils import StaticData


class PcapProcessor(BaseProcessor):

    def __init__(self, config: ConfigurationData, static_data: StaticData = None):
        self.pcap_file_info = PcapFileInfo()
        self.config = config
        self.static_data = static_data
        if self.static_data is None or not isinstance(self.static_data, StaticData):
            self.static_data = StaticData()
        self.dpkt_utils = DpktUtils(config=config, static_data=static_data)

    def open_file(self, file_path: str = None, mode='r'):
        if not file_path:
            raise FileError(
                'No file path specified: {}'.format(file_path),
                error_type=FileErrorTypes.INVALID_FILE_PATH
            )

        try:
            return open(file_path, mode)

        except Exception as ex:
            raise FileError(
                message='Unable to access specified file: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorTypes.UNSPECIFIED_ERROR
            )

    def process(
            self,
            input_file: str = None,
            output_file: str = None,
            pcap_filter: str = ''
    ) -> Tuple[PcapFileInfo, bool]:
        """
        Takes a .pcap_files file as input, reads each packet, extracts basic statistics from the packet and writes them to
        an output file.
        :param input_file: Path to pcap_files file which needs to be processed
        :param output_file: Path to output file where results should be written
        :param pcap_filter: Set up a pypcap's BRF expression to filter packets read from PCAP file. For example,
        to only process DNS packets use pcap_filter='udp dst port 53'.
        :return:
        :raises: FileError
        """
        print('input_file:', input_file)
        pcap_file, captures = self.load_pcap_file_for_reading(input_file, pcap_filter)
        pcap_file_info = PcapFileInfo()
        if pcap_file is None:
            return pcap_file_info, False
        result_file = self.open_output_file_and_write_headers(output_file)
        initial_ts = 0
        # Process packets in PCAP file
        count = 0
        total_data = 0
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
                logging.warning('Unable to process packet at ts:{} Error: {}'.format(ts, ex))
                raise ex

        logging.info('{} packets processed from {}'.format(count, input_file))
        pcap_file.close()
        result_file.close()

        pcap_file_info.file_name = input_file
        pcap_file_info.results_file_name = output_file
        pcap_file_info.start_time = initial_ts
        pcap_file_info.packet_count = count
        pcap_file_info.total_data = total_data

        return pcap_file_info, True

    def open_output_file_and_write_headers(self, output_file_path):
        if not os.path.exists(os.path.dirname(output_file_path)):
            Path(os.path.dirname(output_file_path)).mkdir(parents=True, exist_ok=True)

        output_file = self.open_file(output_file_path, mode='w')         # Overwrites old file
        # Write headers
        output_file.write(PacketData.packet_data_file_headers(delimiter=self.config.ResultFileDelimiter) + '\n')

        return output_file

    def load_pcap_file_for_reading(self, file_path: str, pcap_filter: str = '') -> Tuple:
        try:
            pcap_file = self.open_file(file_path, mode='rb')
            captures = dpkt.pcap.Reader(pcap_file)
            if filter:
                captures.setfilter(pcap_filter)           # pypcap's BRF expression

            return pcap_file, captures

        except Exception as ex:
            logging.warning('Unable to load pcap_files file to dpkt. Error: {}'.format(ex))

        return None, None

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
                logging.debug('Unable to extract layer7 packet with src port `{}`, dst port `{}`'.format(
                    packet_data.src_port, packet_data.dst_port
                ))
            packet_data = self.dpkt_utils.extract_data_from_layer7_packet(layer7_packet, packet_data)

        except Exception as ex:
            logging.error('Error in processing packet at ref_time: {}. Error: {}'.format(packet_data.ref_time, ex))
            print(traceback.format_exc())

        return packet_data
