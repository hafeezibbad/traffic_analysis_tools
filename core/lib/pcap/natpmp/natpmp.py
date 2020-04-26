import struct

from core.lib.pcap.natpmp.common import EXTERNAL_ADDRESS_RESPONSE_FORMAT, NATPMP_REQUEST_FORMAT, \
    PORT_MAPPING_REQUEST_FORMAT, PORT_MAPPING_RESPONSE_FORMAT


class Natpmp:
    """
    NAT Port Mapping Protocol. https://tools.ietf.org/html/rfc6886
    """

    __hdr__ = (
        ('version', 'B'),
        ('opcode', 'B'),
        ('reserved', 'H'),
        ('result', 'H'),
        ('sssoe', 'H'),  # Seconds since start of Epoch (https://tools.ietf.org/html/rfc6886#section-3.6)
        ('lifetime', 'I'),
        ('external_ip', 'I'),
        ('internal_port', 'B'),
        ('external_port', 'B')
    )
    version = -1  # Nat-PMP
    opcode = -1
    reserved = -1
    result = -1
    sssoe = -1
    lifetime = -1
    external_ip = -1
    internal_port = -1
    external_port = -1

    def __init__(self, buf: bytes):
        self.unpack(buf)

    def unpack(self, buf: bytes):
        if len(buf) == 2:   # Public address request
            self.__unpack_pub_address_request(buf)
        elif len(buf) == 12:  # Port mapping request
            unpacked_data = struct.unpack(EXTERNAL_ADDRESS_RESPONSE_FORMAT, buf)
            if unpacked_data[1] == 128:
                self.__unpack_pub_address_response(buf)
            elif unpacked_data[1] == 2:
                # This is port mapping request
                self.__unpacket_port_map_request(buf)
        elif len(buf) >= 16:  # Port mapping response format
            self.__unpack_port_map_response(buf)

    def __unpack_pub_address_request(self, data: bytes):
        self.version, self.opcode = struct.unpack(NATPMP_REQUEST_FORMAT, data)

    def __unpack_pub_address_response(self, data: bytes):
        if len(data) > 12:
            data = data[:12]

        self.version, self.opcode, self.result, self.sssoe, self.external_ip = \
            struct.unpack(EXTERNAL_ADDRESS_RESPONSE_FORMAT, data)

    def __unpacket_port_map_request(self, data: bytes):
        if len(data) > 12:
            data = data[:12]

        self.version, self.opcode, self.reserved, self.internal_port, self.external_port, self.lifetime = \
            struct.unpack(PORT_MAPPING_REQUEST_FORMAT, data)
        print('=' * 80)
        print(self.version, self.opcode, self.reserved, self.internal_port, self.external_port, self.lifetime)
        print('=' * 80)

    def __unpack_port_map_response(self, data: bytes):
        if len(data) > 16:
            data = data[:16]

        self.version, self.opcode, self.result, self.sssoe, self.private_port, self.pub_port, self.lifetime =\
            struct.unpack(PORT_MAPPING_RESPONSE_FORMAT, data)
