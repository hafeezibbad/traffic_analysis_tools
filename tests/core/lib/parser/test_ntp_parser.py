import socket
import dpkt
from munch import Munch

from core.lib.parser.ntp_parser import NtpPacketParser
from tests.core.lib.parser.common import BasePacketParserTests


class NtpPacketParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(NtpPacketParserTests, self).__init__(*args, **kwargs)
        self.ntp_packet_parser = NtpPacketParser(config=self.config)

    def test_extract_data_works_as_expected(self):
        mock_reference_addr = '1.2.3.4'
        mock_interval = 5
        mock_mode = 1
        mock_stratum = 2

        ntp_packet = dpkt.ntp.NTP()
        ntp_packet.mode = mock_mode
        ntp_packet.interval = mock_interval
        ntp_packet.stratum = mock_stratum
        ntp_packet.id = socket.inet_aton(mock_reference_addr)

        ntp_data = self.ntp_packet_parser.extract_data(packet=ntp_packet)

        self.assertIsInstance(ntp_data, Munch)
        self.assertEqual(mock_interval, ntp_data.ntp_interval)
        self.assertEqual(mock_mode, ntp_data.ntp_mode)
        self.assertEqual(mock_stratum, ntp_data.ntp_stratum)
        self.assertEqual(mock_reference_addr, ntp_data.ntp_reference_id)

    def test_resolve_ntp_reference_returns_none_if_id_is_Null(self):
        ntp_packet = dpkt.ntp.NTP()
        ntp_packet.id = b'\x00\x00\x00\x00'

        reference_id = self.ntp_packet_parser.resolve_ntp_reference(ntp_packet)
        self.assertEqual(reference_id, '')

    def test_resolve_ntp_reference_returns_original_id_if_it_can_not_be_parsed_as_ip(self):
        ntp_packet = dpkt.ntp.NTP()
        ntp_packet.id = 1

        reference_id = self.ntp_packet_parser.resolve_ntp_reference(ntp_packet)
        self.assertEqual(1, reference_id)

    def test_resolve_ntp_reference_returns_ip_address_for_reference(self):
        mock_reference_addr = '128.227.205.3'

        ntp_packet = dpkt.ntp.NTP()
        ntp_packet.id = socket.inet_aton(mock_reference_addr)

        reference_id = self.ntp_packet_parser.resolve_ntp_reference(ntp_packet)
        self.assertEqual(mock_reference_addr, reference_id)
