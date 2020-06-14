from typing import Union, Dict, Optional

from typing_extensions import Literal

from core.file_processor.base import FileProcessorBase
from core.models.common import Model


class PcapFileInfo(Model):
    file_name: str = None
    results_file_name: str = None
    file_size: float = 0                # In Kilobytes
    identifier: str = None
    start_time: float = 0               # Unix timestamp when first packet in trace was seen
    stop_time: float = 0                # Unix timestamp when last packet in trace was seen
    total_time: float = 0               # Number of seconds elapsed between seeing the first and last packet in trace.
    total_data: float = 0               # Total data transferred in the trace
    packet_count: float = 0             # Number of packets in the trace
    data_rate: float = 0                # Data/second observed in trace
    average_packet_size: float = 0      # Average packet size observed in trace
    packet_rate: float = 0              # Packet/second observed in trace
    processing_time: float = 0          # Time taken to process the pcap file

    def calculate_summary_stats(self) -> None:
        # Calculate summary statistics for the for trace file summary information
        self.total_time = self.stop_time - self.start_time
        if self.total_time != 0:
            self.data_rate = self.total_data / self.total_time
            self.packet_rate = self.packet_count / self.total_time
            self.average_packet_size = self.total_data / self.packet_count

    def get_summary(
            self, output_format: Literal['json', 'csv'] = 'json'
    ) -> Optional[Union[Dict[str, str], str]]:
        summary_data = None
        self.calculate_summary_stats()
        self.file_size = FileProcessorBase().get_file_size(file_path=self.file_name)
        if output_format.lower() == 'json':
            summary_data = self.to_json()

        if output_format.lower() == 'csv':
            summary_data = self.to_csv_string()

        return summary_data

    def get_trace_file_info_csv_headers(self, delimiter: str = ',') -> str:
        return delimiter.join([
            "file_name",
            "results_file_name",
            "file_size",
            "identifier",
            "start_time",
            "stop_time",
            "total_time",
            "total_data",
            "packet_count",
            "data_rate",
            "average_packet_size",
            "packet_rate"
        ])

    def to_csv_string(self, delimiter: str = ',') -> str:
        return delimiter.join([
            self.file_name,
            self.results_file_name,
            self.file_size,
            self.identifier,
            self.start_time,
            self.stop_time,
            self.total_time,
            self.total_data,
            self.packet_count,
            self.data_rate,
            self.average_packet_size,
            self.packet_rate
        ])
