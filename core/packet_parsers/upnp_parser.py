import logging

from typing import Union
import dpkt
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.packet_parsers.base import PacketParserInterface
from core.pcap.upnp.upnp_request import UpnpRequest


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
        fingerprint = Munch()

        fingerprint.upnp_packet_type = 1
        fingerprint.upnp_location = http_packet.headers.get("location")
        fingerprint.upnp_server = http_packet.headers.get("server")
        if "cache-control" in http_packet.headers:
            fingerprint.upnp_cache = int(http_packet.headers.get("cache-control").split('=')[1])
        fingerprint.upnp_uns = http_packet.headers.get("usn")
        fingerprint.upnp_nt = http_packet.headers.get("nt")
        fingerprint.upnp_nts = http_packet.headers.get("nts")

        return fingerprint

    def extract_fingerprint_from_msearch_message(self, http_packet: dpkt.http.Request) -> Munch:
        fingerprint = Munch()

        fingerprint.upnp_packet_type = 2
        fingerprint.upnp_host = http_packet.headers.get('host', '')
        fingerprint.upnp_st = http_packet.headers.get('st', '')
        fingerprint.upnp_man = http_packet.headers.get('man', '')
        fingerprint.upnp_mx = http_packet.headers.get('mx')

        return fingerprint

    def extract_fingerprint_from_request(self, http_packet: UpnpRequest) -> dict:
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

    def extract_fingerprint_from_response(self, upnp_packet: dpkt.http.Response) -> dict:
        fingerprint = dict()
        if upnp_packet is None:
            return fingerprint

        fingerprint = self.extract_fingerprint_from_notify_message(upnp_packet)
        return fingerprint

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
