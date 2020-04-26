from core.lib.parser.natpmp_parser import NatpmpPacketParser
from core.lib.pcap.natpmp.natpmp import Natpmp
from core.lib.pcap.natpmp.natpmp_requests import ExternalAddressRequest, PortMappingRequest
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
        mock_protocol = 0
        mock_version = 1
        natpmp_request = PortMappingRequest(
            protocol=mock_protocol,
            private_port=mock_private_port,
            public_port=mock_public_port,
            lifetime=mock_lifetime,
            version=mock_version
        )
        print(natpmp_request.to_bytes())
        natpmp_packet = Natpmp(natpmp_request.to_bytes())
        natpmp_data = self.natpmp_packet_parser.extract_data(natpmp_packet)

        self.assertEqual(mock_private_port, natpmp_data.natpmp_internal_port)
        self.assertEqual(mock_public_port, natpmp_data.natpmp_external_port)
        self.assertEqual(mock_lifetime, natpmp_data.natpmp_lifetime)
        self.assertEqual(mock_protocol, natpmp_data.natpmp_opcode)
        self.assertEqual(mock_version, natpmp_data.natpmp_version)
