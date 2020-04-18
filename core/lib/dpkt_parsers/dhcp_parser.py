import logging
from typing import Optional

import dpkt
from dpkt.dhcp import DHCP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.base import PacketParserInterface


class DhcpPacketParser(PacketParserInterface):
    def __init__(self, config: ConfigurationData):
        self.config = config

    def extract_data(self, packet: DHCP) -> Munch:
        data = Munch()

        dhcp_options = self.extract_dhcp_options_from_dhcp_packet(packet)
        if dhcp_options is None:
            logging.warning('Unable to extract options from DHCP packet')
            return data

        try:
            data.dhcp_fingerprint = self.extract_fingerprint_from_dhcp_options(dhcp_options) or ''
            data.dhcp_vendor = self.extract_vendor_from_dhcp_options(dhcp_options) or ''
            data.dhcp_hostname = self.extract_dhcp_hostname_from_dhcp_options(dhcp_options) or ''

        except BaseException as ex:
            logging.warning('Unable to extract data from `{}`.Error: `{}`'.format(type(packet), ex))
            raise ex

        return data

    def extract_dhcp_options_from_dhcp_packet(self, dhcp_packet: DHCP) -> Optional[dict]:
        dhcp_options = None
        try:
            dhcp_options = dict(dhcp_packet.opts)

        except ValueError:
            logging.warning('Failed to extract dhcp_options from DHCP packet. Invalid type: `{}` of '
                            '`dhcp_packet.opts`'.format(type(dhcp_packet.opts)))

        return dhcp_options

    def extract_fingerprint_from_dhcp_options(self, dhcp_options: dict) -> Optional[str]:
        if dpkt.dhcp.DHCP_OPT_PARAM_REQ not in dhcp_options:
            logging.debug('DHCP_OPT_PARAM_REQ not specified in DHCP packet options')

            return ''

        return self.config.FieldDelimiter.join([str(x) for x in dhcp_options])

    def extract_vendor_from_dhcp_options(self, dhcp_options: dict) -> Optional[str]:
        vendor_option = None
        if dpkt.dhcp.DHCP_OPT_VENDOR_ID in dhcp_options:
            try:
                vendor_option = dhcp_options.get(dpkt.dhcp.DHCP_OPT_VENDOR_ID, '').decode('utf-8')

            except AttributeError:
                # TODO: better error handling
                logging.warning('Failed to extract information from DHCP packet. Invalid type of dhcp_vendor_option')

        return vendor_option

    def extract_dhcp_hostname_from_dhcp_options(self, dhcp_options: dict) -> Optional[str]:
        dhcp_hostname = None
        if dpkt.dhcp.DHCP_OPT_HOSTNAME in dhcp_options:
            try:
                dhcp_hostname = dhcp_options.get(dpkt.dhcp.DHCP_OPT_HOSTNAME, '').decode('utf-8')

            except AttributeError:
                # TODO: better error handling
                logging.warning('Failed to extract vendor information from DHCP packet. Invalid type of dhcp_hostname')

        return dhcp_hostname

    @staticmethod
    def load_dhcp_from_udp_packet(udp_packet):
        dhcp = None
        try:
            dhcp = dpkt.dhcp.DHCP(udp_packet.data)

        except BaseException as ex:
            logging.warning('Unable to extract DHCP packet from UDP packet. Error: {}'.format(ex))

        return dhcp