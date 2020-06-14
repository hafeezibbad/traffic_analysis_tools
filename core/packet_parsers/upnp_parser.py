import logging
import re

from typing import Union, Dict
import dpkt
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch, DefaultMunch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface
from core.pcap.upnp.upnp_request import UpnpRequest
from core.static.patterns import UPNP_VERSION_REGEX


class UpnpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    @staticmethod
    def load_upnp_request_from_ip_packet(ip_packet: IP) -> UpnpRequest:
        try:
            udp_packet = UDP(ip_packet.data)
            return UpnpPacketParser.load_upnp_packet_from_udp_packet(udp_packet)

        except BaseException as ex:
            logging.warning('Can not extract UPnP request from IP packet. Error: `%s`', ex)
            raise ex

    @staticmethod
    def load_upnp_packet_from_udp_packet(udp_packet: UDP) -> UpnpRequest:
        try:
            http_packet = UpnpRequest(udp_packet.data)
            if http_packet.method not in ['NOTIFY', 'M-SEARCH']:
                http_packet = dpkt.http.Response(udp_packet.data)

            return http_packet

        except BaseException as ex:
            logging.warning('Can not extract UPnP request from IP packet. Error: `%s`', ex)
            raise ex

    def extract_fingerprint_from_notify_message(self, http_packet: dpkt.http.Request) -> Munch:
        # Note that the library will accept any case of header, they are lowercase in the result
        fingerprint = DefaultMunch('')

        fingerprint.upnp_packet_type = 1
        fingerprint.upnp_location = http_packet.headers.get("location")
        fingerprint.upnp_uns = http_packet.headers.get("usn")
        fingerprint.upnp_nt = http_packet.headers.get("nt")
        fingerprint.upnp_nts = http_packet.headers.get("nts")

        if http_packet.headers.get('server'):
            fingerprint.update(self.parse_upnp_header_information(http_packet.headers.get('server')))
        if "cache-control" in http_packet.headers:
            fingerprint.upnp_cache = int(http_packet.headers.get("cache-control").split('=')[1])

        return fingerprint

    def extract_fingerprint_from_msearch_message(self, http_packet: dpkt.http.Request) -> Munch:
        fingerprint = Munch()

        fingerprint.upnp_packet_type = 2
        fingerprint.upnp_host = http_packet.headers.get('host', '')
        fingerprint.upnp_st = http_packet.headers.get('st', '')
        fingerprint.upnp_man = http_packet.headers.get('man', '')
        fingerprint.upnp_mx = http_packet.headers.get('mx')
        fingerprint.upnp_user_agent = http_packet.headers.get('user-agent')
        if http_packet.headers.get('user-agent'):
            fingerprint.update(self.parse_upnp_header_information(http_packet.headers.get('user-agent')))

        return fingerprint

    def extract_fingerprint_from_request(self, http_packet: UpnpRequest) -> Dict[str, str]:
        fingerprint = dict()
        try:
            if http_packet.method == "NOTIFY":
                # SSDP uses the HTTP method NOTIFY to announce the establishment or withdrawal of services (presence)
                # information to the multicast group
                fingerprint = self.extract_fingerprint_from_notify_message(http_packet)

            elif http_packet.method == "M-SEARCH":
                # A client that wishes to discover available services on a network, uses method M-SEARCH
                fingerprint = self.extract_fingerprint_from_msearch_message(http_packet)

        except AttributeError as ex:
            logging.warning('HTTP packet extracted from UPnP packet does not have attribute `method`')
            raise ex

        return fingerprint

    def extract_fingerprint_from_response(self, upnp_packet: dpkt.http.Response) -> Dict[str, str]:
        fingerprint = dict()
        if upnp_packet is None:
            return fingerprint

        fingerprint = self.extract_fingerprint_from_notify_message(upnp_packet)
        return fingerprint

    def parse_upnp_header_information(self, upnp_header_data: str = None) -> Munch:
        """Parse info available in UPnP message server field to extract os and production information.

        Description of data available in server field (in UPnP packet) available here.
        http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
             SERVER
                REQUIRED. Specified by UPnP vendor. String. Field value MUST begin with the following “product
                tokens” (defined by HTTP/1.1). The first product token identifes the operating system in the form OS
                name/OS version, the second token represents the UPnP version and MUST be UPnP/1.1, and the third
                token identifes the product using the form product name/product version. For example,
                “SERVER: unix/5.1 UPnP/1.1 MyProduct/1.0”. Control points MUST be prepared to accept a higher minor
                version number of the UPnP version than the control point itself implements. For example,
                control points implementing UDA version 1.0 will be able to interoperate with devices implementing
                UDA version 1.1.
            USER-AGENT
                OPTIONAL. Specified by UPnP vendor. String. Field value MUST begin with the following “product tokens”
                (defined by HTTP/1.1). The first product token identifes the operating system in the form OS name/OS
                version, the second token represents the UPnP version and MUST be UPnP/1.1, and the third token
                identifes the product using the form  product name/product version. For example, “USER-AGENT:
                unix/5.1 UPnP/1.1 MyProduct/1.0”. Control points MUST be prepared to accept a higher minor version
                number of the UPnP version than the control point itself implements. For example, control points
                implementing UDA version 1.0 will be able to interoperate with devices implementing UDA version 1.1.

        Parameters
        ----------
        upnp_header_data: str
            Data extracted from server field in UPnP packet. Default=None

        Returns
        --------
        upnp_info: Munch
            Munch object containing os_name, os_version, product_name, and product_version information.
        """
        upnp_info = DefaultMunch('')
        if not upnp_header_data:
            return upnp_info

        upnp_data = re.split(UPNP_VERSION_REGEX, upnp_header_data)
        if len(upnp_data) != 2:
            return upnp_info

        if upnp_data[0].lower() != 'Undefined':
            _data = re.sub(',\s', '', upnp_data[0])
            upnp_info.upnp_os_name, _, upnp_info.upnp_os_version = \
                _data.strip().replace(',', '').partition('/')

        if upnp_data[1].lower() != 'Undefined':
            _data = re.sub(',\s', '', upnp_data[1])
            upnp_info.upnp_product_name, _, upnp_info.upnp_product_version = \
                _data.strip().replace(',', '').partition('/')

        m = re.search(UPNP_VERSION_REGEX, upnp_header_data)
        if m:
            upnp_info.upnp_version = m.group(0).split('/')[1]

        return upnp_info

    def extract_data(self, packet: Union[UpnpRequest, dpkt.http.Response]) -> Munch:
        """Extract data from UPnP response or response packet. The data is extracted from the packet based on
        HTTP request  method. The data consists of headers and packet data included in UPnP packet.

        Parameters
        ----------
        packet: UPnP request or response packet.

        Returns
        -------
        Dictionary (Munch) object containing fingerprint data extracted from UPnP request or response

        Raises
        -------
        Attribute error: Raised while extracting fingerprint from UPnP request or response.
        """
        data = Munch()
        fingerprint = dict()
        if packet is None:
            return data

        if isinstance(packet, UpnpRequest):
            data.upnp_packet_type = 1
            fingerprint = self.extract_fingerprint_from_request(packet)

        elif isinstance(packet, dpkt.http.Response):
            data.upnp_packet_type = 2
            fingerprint = self.extract_fingerprint_from_response(packet)

        for key, value in fingerprint.items():
            data[key] = value

        return data
