import dpkt
from munch import Munch

from core.packet_parsers.layer4_parser import Layer4PacketParser
from tests.core.packet_parsers.common import BasePacketParserTests
from tests.fixtures.protocols import PORT_INFO_WO_ABBRV


class Layer4BaseParserTests(BasePacketParserTests):
    def __init__(self, *args, **kwargs):
        super(Layer4BaseParserTests, self).__init__(*args, **kwargs)
        self.layer4_packet_parser = Layer4PacketParser(config=self.config)

    def test_extract_common_data_works_as_expected(self):
        mock_data = b'12345'
        mock_src_port = 11123
        mock_dst_port = 53
        mock_protocol = 'dns'
        mock_flags = 0x010

        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = mock_src_port
        layer4_packet.dport = mock_dst_port
        layer4_packet.flags = mock_flags
        layer4_packet.data = mock_data

        data = self.layer4_packet_parser.extract_common_data(
            protocol_type='tcp',
            packet=layer4_packet
        )

        self.assertIsInstance(data, Munch)
        self.assertEqual(mock_src_port, data.src_port)
        self.assertEqual(mock_dst_port, data.dst_port)
        self.assertTrue(data.outgoing)
        self.assertEqual(mock_protocol, data.layer7_proto)
        self.assertEqual(len(mock_data), data.layer4_payload_size)

    def test_extract_data_raises_not_implemented_error(self):
        layer4_packet = dpkt.tcp.TCP()
        with self.assertRaises(NotImplementedError):
            self.layer4_packet_parser.extract_data(layer4_packet)

    def test_is_packet_outgoing_returns_true_if_source_port_is_not_in_range(self):
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = 15000

        self.assertTrue(self.layer4_packet_parser.is_packet_outgoing(layer4_packet))

    def test_is_packet_outgoing_returns_false_if_source_port_is_in_range(self):
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = 9999
        self.assertFalse(self.layer4_packet_parser.is_packet_outgoing(layer4_packet))

    def test_is_packet_outgoing_ranges_work_as_expected(self):
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = 10000
        self.assertTrue(self.layer4_packet_parser.is_packet_outgoing(layer4_packet))

    def test_extract_src_dest_port_work_as_expected(self):
        mock_src_port = 50000
        mock_dst_port = 443
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = mock_src_port
        layer4_packet.dport = mock_dst_port

        self.assertEqual((mock_src_port, mock_dst_port), self.layer4_packet_parser.extract_src_dest_port(layer4_packet))

    def test_get_layer7_proto_number_returns_none_if_packet_is_none(self):
        self.assertIsNone(self.layer4_packet_parser.get_layer7_protocol('tcp', None))

    def test_get_layer7_proto_number_returns_dst_port_if_packet_is_outgoing(self):
        mock_protocol = 'https'
        mock_src_port = 50000
        mock_dst_port = 443      # Packet is outgoing
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = mock_src_port
        layer4_packet.dport = mock_dst_port

        self.assertEqual(mock_protocol, self.layer4_packet_parser.get_layer7_protocol('tcp', layer4_packet))

    def test_get_layer7_proto_number_returns_src_port_if_packet_is_incoming(self):
        mock_protocol = 'https'
        mock_src_port = 443      # Packet is incoming
        mock_dst_port = 50000
        layer4_packet = dpkt.tcp.TCP()
        layer4_packet.sport = mock_src_port
        layer4_packet.dport = mock_dst_port

        self.assertEqual(mock_protocol, self.layer4_packet_parser.get_layer7_protocol('tcp', layer4_packet))

    def test_get_protocol_info_from_port_works_as_expected_for_tcp_protocol(self):
        self.assertStrEqual(
            'https',
            self.layer4_packet_parser.get_protocol_info_from_port(port_number=443, protocol_type='tcp'),
            ignore_case=True
        )

    def test_get_protocol_info_from_port_works_as_expected_for_udp_protocol(self):
        self.assertStrEqual(
            'dns',
            self.layer4_packet_parser.get_protocol_info_from_port(port_number=53, protocol_type='udp'),
            ignore_case=True
        )

    def test_get_protocol_info_returns_none_if_status_data_does_not_contain_port(self):
        self.assertIsNone(self.layer4_packet_parser.get_protocol_info_from_port(port_number=35000, protocol_type='udp'))

    def test_extract_protocol_info_returns_none_if_protocol_type_in_layer4_protocols(self):
        self.assertEqual(
            ('', ''),
            self.layer4_packet_parser.extract_protocol_info_from_protocol_data(data=dict(), protocol_type='dns')
        )

    def test_extract_protocol_info_returns_none_if_no_data_for_protocol_type(self):
        mock_data = {
            'tcp': True,
            'udp': False,
            'abbrv': 'mock_abbrv',
            'description': 'mock_description'
        }
        self.assertEqual(
            ('', ''),
            self.layer4_packet_parser.extract_protocol_info_from_protocol_data(data=mock_data, protocol_type='udp')
        )

    def test_extract_protocol_info_works_as_expected(self):
        mock_data = {
            'tcp': True,
            'udp': False,
            'abbrv': 'mock_abbrv',
            'description': 'mock_description'
        }
        self.assertEqual(
            ('mock_abbrv', 'mock_description'),
            self.layer4_packet_parser.extract_protocol_info_from_protocol_data(data=mock_data, protocol_type='tcp')
        )

    def test_get_protocol_info_from_protocol_data_works_as_expected_when_there_is_only_one_item_protocol_data(self):
        mock_data = {
            'tcp': True,
            'udp': False,
            'abbrv': 'mock_abbrv',
            'description': 'mock_description'
        }
        self.assertEqual(
            ('mock_abbrv', 'mock_description'),
            self.layer4_packet_parser.get_protocol_info_from_protocol_data(data=mock_data, protocol_type='tcp')
        )

    def test_get_protocol_info_works_as_expected_with_multiple_item_in_protocol_data(self):
        mock_data = [
            {
                'tcp': True,
                'udp': False,
                'abbrv': 'mock_abbrv1',
                'description': 'mock_description1'
            },
            {
                'tcp': True,
                'udp': False,
                'abbrv': 'mock_abbrv2',
                'description': 'mock_description2'
            }
        ]
        self.assertEqual(
            ('mock_abbrv1;mock_abbrv2', 'mock_description1;mock_description2'),
            self.layer4_packet_parser.get_protocol_info_from_protocol_data(data=mock_data, protocol_type='tcp')
        )

    def test_get_protocol_info_from_protocol_data_returns_none_as_default(self):
        self.assertEqual(
            (None, None),
            self.layer4_packet_parser.get_protocol_info_from_protocol_data(data=1234, protocol_type='tcp')
        )

    def test_get_protocol_info_from_port_returns_description_if_no_abbrv(self):
        self.assertEqual(
            self.layer4_packet_parser.get_protocol_info_from_port(973, protocol_type="udp"),
            PORT_INFO_WO_ABBRV["description"]
        )
