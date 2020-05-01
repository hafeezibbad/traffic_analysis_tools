import struct

from core.pcap.natpmp.common import NATPMP_RESPONSE_FORMAT, EXTERNAL_ADDRESS_RESPONSE_FORMAT, \
    PORT_MAPPING_RESPONSE_FORMAT


class NatpmpResponseBuilder:
    """Create NAT-PMP response coming from local gateway."""
    def __init__(self, version: int, opcode: int, result: int, sec_since_epoch: int) -> None:
        self.version = version
        self.opcode = opcode
        self.result = result
        self.sec_since_epoch = sec_since_epoch

    def to_bytes(self):
        """Convert NAT-PMP response to bytes"""
        return struct.pack(NATPMP_RESPONSE_FORMAT, self.version, self.opcode, self.result, self.sec_since_epoch)


class ExternalAddressResponseBuilder(NatpmpResponseBuilder):
    def __init__(
            self,
            version: int,
            opcode: int,
            result: int,
            sec_since_epoch: int,
            integer_ip: int,
            reserved: int = 0
    ) -> None:
        super(ExternalAddressResponseBuilder, self).__init__(version, opcode, result, sec_since_epoch)
        self.integer_ip = integer_ip
        self.reserved = reserved

    def to_bytes(self):
        return struct.pack(
            EXTERNAL_ADDRESS_RESPONSE_FORMAT,
            self.version,
            self.opcode,
            self.result,
            self.sec_since_epoch,
            self.integer_ip
        )


class PortMappingResponseBuilder(NatpmpResponseBuilder):
    def __init__(
            self,
            version: int,
            opcode: int,
            result: int,
            sec_since_epoch: int,
            private_port: int,
            public_port: int,
            lifetime: int
    ) -> None:
        self.private_port = private_port
        self.public_port = public_port
        self.lifetime = lifetime
        super(PortMappingResponseBuilder, self).__init__(version, opcode, result, sec_since_epoch)

    def to_bytes(self):
        return struct.pack(
            PORT_MAPPING_RESPONSE_FORMAT,
            self.version,
            self.opcode,
            self.result,
            self.sec_since_epoch,
            self.private_port,
            self.public_port,
            self.lifetime
        )
