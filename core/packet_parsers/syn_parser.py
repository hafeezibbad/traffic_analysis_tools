import logging
import re
import subprocess
from tempfile import NamedTemporaryFile

import dpkt
from dpkt.ip import IP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface


class SynPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def write_ip_to_pcap(self, pcapfile, ip):
        """Write the given IP packet into a PCAP file."""
        # MAC addresses here are irrelevant (I hope), but required for p0f to be not confused
        eth = dpkt.ethernet.Ethernet(
            dst=b"\x08\x00\x27\x70\xe3\xf0",
            src=b"\x08\x00\x27\x70\xa3\xf0",
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        eth.data = ip

        writer = dpkt.pcap.Writer(pcapfile)
        writer.writepkt(bytes(eth))

        pcapfile.flush()
        pcapfile.close()

    def extract_signature_from_syn_using_p0f(self, p0f_executable, p0f_wd, ip_packet):
        result = None
        try:
            with NamedTemporaryFile(delete=False) as pcap_file:
                self.write_ip_to_pcap(pcap_file, ip_packet)

                result = subprocess.run(                        # pylint: disable=subprocess-run-check
                    [p0f_executable, "-r", pcap_file.name],
                    cwd=p0f_wd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                )

        except ValueError as ex:
            logging.warning('Unable to extract signature from SYN packet using `p0f`. Error: `%s`', ex)

        return result

    def extract_signature_from_p0f_output(self, p0f_output) -> str:
        fingerprint = dict()

        signature = re.search(r'raw_sig += +(.*)', p0f_output)
        if signature:
            fingerprint["tcp_syn_signatures"] = signature.group(1).replace(',', self.config.FieldDelimiter)

        return fingerprint.get("tcp_syn_signatures", '')

    def extract_os_from_p0f_output(self, p0f_output) -> str:
        client_os = ''
        os_info = re.search(r'os += +(.*)', p0f_output)
        if os_info:
            client_os = os_info.group(1)

        return client_os

    def extract_data(self, packet: IP) -> Munch:
        data = Munch()
        result = self.extract_signature_from_syn_using_p0f(
            p0f_executable=self.config.p0f_executable,
            p0f_wd=self.config.p0f_wd,
            ip_packet=packet
        )

        try:
            if result.returncode != 0:
                return data

            data.syn_signature = self.extract_signature_from_p0f_output(p0f_output=result.stdout)
            data.client_os = self.extract_os_from_p0f_output(p0f_output=result.stdout)

        except BaseException as ex:
            logging.warning('Failed to extract signature from TCP-SYN packet. Error: `%s`', ex)

        return data
