from core.lib.ip_utils import IpAddrUtils
from core.lib.parser.natpmp_parser import NatpmpPacketParser
from core.lib.pcap.natpmp.natpmp import Natpmp
from core.lib.pcap.natpmp.natpmp_requests import ExternalAddressRequest, PortMappingRequest
from core.lib.pcap.natpmp.natpmp_response_builder import ExternalAddressResponseBuilder, PortMappingResponseBuilder
from tests.core.lib.parser.common import BasePacketParserTests


class NatpmpParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(NatpmpParserTests, self).__init__(*args, **kwargs)
        self.natpmp_packet_parser = NatpmpPacketParser(config=self.config)

    def test_natpmp_external_address_request_parsed_as_expected(self):
        natpmp_request = ExternalAddressRequest(version=0, opcode=0)
        natpmp_packet = Natpmp(natpmp_request.to_bytes())
        natpmp_data = self.natpmp_packet_parser.extract_data(natpmp_packet)

        self.assertEqual(0, natpmp_data.natpmp_version)
        self.assertEqual(0, natpmp_data.natpmp_opcode)

    def test_natpmp_port_mapping_request_parsed_as_expected(self):
        mock_private_port = 1234
        mock_public_port = 4321
        mock_lifetime = 666
        mock_protocol = 2  # OPcode= 2 for port mapping request.
        mock_version = 1
        natpmp_request = PortMappingRequest(
            protocol=mock_protocol,
            private_port=mock_private_port,
            public_port=mock_public_port,
            lifetime=mock_lifetime,
            version=mock_version
        )
        natpmp_packet = Natpmp(natpmp_request.to_bytes())
        natpmp_data = self.natpmp_packet_parser.extract_data(natpmp_packet)

        self.assertEqual(mock_private_port, natpmp_data.natpmp_internal_port)
        self.assertEqual(mock_public_port, natpmp_data.natpmp_external_port)
        self.assertEqual(mock_lifetime, natpmp_data.natpmp_lifetime)
        self.assertEqual(mock_protocol, natpmp_data.natpmp_opcode)
        self.assertEqual(mock_version, natpmp_data.natpmp_version)

    def test_natpmp_external_address_response_parsed_as_expected(self):
        mock_version = 1
        mock_opcode = 128
        mock_result = 0
        mock_sec_since_epoch = 1800
        mock_ip = '1.1.1.1'
        mock_ip_int = IpAddrUtils().ip_to_int(mock_ip)

        natpmp_response = ExternalAddressResponseBuilder(
            version=mock_version,
            opcode=mock_opcode,
            result=mock_result,
            sec_since_epoch=mock_sec_since_epoch,
            integer_ip=mock_ip_int
        )
        natpmp_packet = Natpmp(natpmp_response.to_bytes())
        natpmp_data = self.natpmp_packet_parser.extract_data(natpmp_packet)

        self.assertEqual(mock_version, natpmp_data.natpmp_version)
        self.assertEqual(mock_opcode, natpmp_data.natpmp_opcode)
        self.assertEqual(mock_result, natpmp_data.natpmp_result)
        self.assertEqual(mock_sec_since_epoch, natpmp_data.natpmp_sssoe)
        self.assertEqual(mock_ip_int, natpmp_data.natpmp_external_ip)

    def test_natpmp_port_mapping_response_parsed_as_expected(self):
        mock_version = 1
        mock_opcode = 130  # 128+2
        mock_result = 0
        mock_sec_since_epoch = 1800
        mock_private_port = 1234
        mock_public_port = 4321
        mock_lifetime = 3600

        natpmp_response = PortMappingResponseBuilder(
            version=mock_version,
            opcode=mock_opcode,
            result=mock_result,
            sec_since_epoch=mock_sec_since_epoch,
            private_port=mock_private_port,
            public_port=mock_public_port,
            lifetime=mock_lifetime
        )
        natpmp_packet = Natpmp(natpmp_response.to_bytes())
        natpmp_data = self.natpmp_packet_parser.extract_data(natpmp_packet)

        self.assertEqual(mock_version, natpmp_data.natpmp_version)
        self.assertEqual(mock_opcode, natpmp_data.natpmp_opcode)
        self.assertEqual(mock_result, natpmp_data.natpmp_result)
        self.assertEqual(mock_sec_since_epoch, natpmp_data.natpmp_sssoe)
        self.assertEqual(mock_private_port, natpmp_data.natpmp_internal_port)
        self.assertEqual(mock_public_port, natpmp_data.natpmp_external_port)
        self.assertEqual(mock_lifetime, natpmp_data.natpmp_lifetime)
