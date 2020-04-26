import struct

from core.lib.ip_utils import IpAddrUtils
from core.lib.pcap.natpmp.common import EXTERNAL_ADDRESS_RESPONSE_FORMAT, PORT_MAPPING_RESPONSE_FORMAT


class NatpmpResponse:
    """
    Creates generic response for NAT-PMP request to local gateway. This generic response contains version (B: 1-byte
    unsigned short), opcode (B: 1-byte unsigned short), result, seconds since last epoch (last boot time of NAT
    gateway). Opcode in response is 128 bit offset from opcode in original NAT-PMP request.
    """
    def __init__(self, version: int, opcode: int, result: str, sec_since_epoch: int):
        self.version = version
        self.opcode = opcode
        self.result = result
        self.sec_since_epoch = sec_since_epoch

    def __str__(self):
        return "NAT-PMP Response: version={ver}, opcode={op}, result={res}, sec_since_epoch={sec})".format(
            ver=self.version,
            op=self.opcode,
            res=self.result,
            sec=self.sec_since_epoch
        )


class ExternalAddressResponse(NatpmpResponse):
    """
    Decodes response from local gateway for external address request to local gateway. In addition to the fields
    specified in request containing IP address. The member variable IP contains string format for IP address and
    integer_ip is of I: 4-byte unsigned integer format.
    """
    def __init__(self, data: bytes) -> None:
        if len(data) > 12:
            data = data[:12]

        version, opcode, result, sec_since_epoch, self.integer_ip = \
            struct.unpack(EXTERNAL_ADDRESS_RESPONSE_FORMAT, data)
        super(ExternalAddressResponse, self).__init__(version, opcode, result, sec_since_epoch)
        self.ip = IpAddrUtils().int_to_ip(self.integer_ip)

    def __str__(self):
        return \
            "ExternalAddressResponse: version={ver}, opcode={op}, result={res}, sec_since_epoch={sec}, ip={ip}".format(
                ver=self.version,
                op=self.opcode,
                res=self.result,
                sec=self.sec_since_epoch,
                ip=self.ip
            )


class PortMappingResponse(NatpmpResponse):
    """
    Decodes response for PortMappingRequest to local gateway. The response contains private_port (H: 2-byte unsigned
    short), public_port (H: 2-byte unsigned short), lifetime (I: 4-byte unsigned integer) in addition to NAT-PMP
    headers. Please note that the port mapping assigned is NOT NECESSARILY the port request.
    """
    def __init__(self, data: bytes) -> None:
        if len(data) > 16:
            data = data[:16]

        version, opcode, result, sec_since_epoch, self.private_port, self.public_port, self.lifetime = \
            struct.unpack(PORT_MAPPING_RESPONSE_FORMAT, data)
        super(PortMappingResponse, self).__init__(version, opcode, result, sec_since_epoch)

    def __str__(self):
        return \
            "PortMappingResponse: version={ver}, opcode={op}, result={res}, sec_since_epoch={sec}, private_port=" \
            "{priv_port}, public_port={pub_port}, lifetime={lifetime}".format(
                ver=self.version,
                op=self.opcode,
                res=self.result,
                sec=self.sec_since_epoch,
                priv_port=self.private_port,
                pub_port=self.public_port,
                lifetime=self.lifetime
            )
