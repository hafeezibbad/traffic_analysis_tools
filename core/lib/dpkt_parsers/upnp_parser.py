import logging

import dpkt
from dpkt.ip import IP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface
from core.lib.dpkt_parsers.upnp_request import UpnpRequest


class UpnpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    @staticmethod
    def extract_upnp_request_from_ip_packet(ip_packet: IP) -> UpnpRequest:
        try:
            udp_packet = UDP(ip_packet.data)
            return UpnpRequest(udp_packet.data)

        except BaseException as ex:
            logging.warning('Can not extract UPnP request from IP packet. Error: {}'.format(ex))
            raise ex

    @staticmethod
    def extract_upnp_request_from_udp_packet(udp_packet: UDP) -> UpnpRequest:
        try:
            return UpnpRequest(udp_packet.data)

        except BaseException as ex:
            logging.error('Can not extract UPnP request from UDP packet. Error: {}'.format(ex))
            raise ex

    def extract_http_response_from_udp_packet(self, udp_packet: dpkt.udp.UDP) -> dpkt.http.Response:
        try:
            return dpkt.http.Response(udp_packet.data)

        except BaseException as ex:
            logging.warning('Can not extract HTTP Response from UPnP packet. Error: {}'.format(ex))
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

    def extract_fingerprint_from_http_request(self, http_packet: dpkt.http.Request) -> dict:
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

    # pylint: disable=invalid-name
    def extract_fingerprint_from_http_response_in_udp_packet(self, udp_packet: dpkt.udp.UDP) -> dict:
        fingerprint = dict()
        http_response_packet = self.extract_http_response_from_udp_packet(udp_packet)
        if http_response_packet is None:
            return fingerprint

        fingerprint = self.extract_fingerprint_from_notify_message(http_response_packet)
        return fingerprint

    def extract_data(self, udp_packet: UDP) -> Munch:
        data = Munch()

        try:
            http_packet = self.extract_upnp_request_from_udp_packet(udp_packet)
            if http_packet is None:
                return data

            fingerprint = self.extract_fingerprint_from_http_request(http_packet)
            data.upnp_packet_type = 1

            if not fingerprint:  # Fingerprint is empty dictionary
                fingerprint = self.extract_fingerprint_from_http_response_in_udp_packet(udp_packet)
                data.upnp_packet_type = 2

            for key, value in fingerprint.items():
                data[key] = value

        except BaseException as ex:
            raise ex

        return data
