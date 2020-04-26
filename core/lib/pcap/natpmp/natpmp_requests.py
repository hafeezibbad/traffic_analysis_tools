import struct

from core.lib.pcap.natpmp.common import NATPMP_REQUEST_FORMAT, PORT_MAPPING_REQUEST_FORMAT, NATPMP_RESERVED_VALUE


class NatpmpRequest:
    """
    Create a basic NAT-PMP request which consist of version (B: 1-byte unsigned short) and opcode
    (B: 1-byte unsigned short) fields.
    """
    def __init__(self, version: int = 0, opcode: int = 0) -> None:
        self.version = version
        self.opcode = opcode

    def to_bytes(self) -> bytes:
        return struct.pack(NATPMP_REQUEST_FORMAT, self.version, self.opcode)


class ExternalAddressRequest(NatpmpRequest):
    """Create a NAT-PMP request (to local gateway) for external address. This is generic request with opcode=0"""
    def __init__(self, version: int = 0, opcode: int = 0) -> None:
        super(ExternalAddressRequest, self).__init__(version=version, opcode=opcode)


class PortMappingRequest(NatpmpRequest):
    """
    Create a NAT-PMP TCP port mapping request. The additional fields for this request include private_port
    (H: 2-byte unsigned short), public_port (H: 2-byte unsigned short), and lifetime (I: 4-byte unsigned integer).
    """
    def __init__(self, protocol: int, private_port: int, public_port: int, lifetime: int = 3600, version: int = 0):
        super(PortMappingRequest, self).__init__(version, protocol)
        self.private_port = private_port
        self.public_port = public_port
        self.lifetime = lifetime

    def to_bytes(self):
        return struct.pack(
            PORT_MAPPING_REQUEST_FORMAT,
            self.version,
            self.opcode,
            NATPMP_RESERVED_VALUE,
            self.private_port,
            self.public_port,
            self.lifetime
        )

