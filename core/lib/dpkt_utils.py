import logging
from typing import Callable, Union

import dpkt
from dpkt.arp import ARP
from dpkt.dhcp import DHCP, DHCP_OPT_POP3SERVER
from dpkt.dns import DNS
from dpkt.ethernet import Ethernet
from dpkt.icmp import ICMP
from dpkt.icmp6 import ICMP6
from dpkt.igmp import IGMP
from dpkt.ip import IP
from dpkt.llc import LLC
from dpkt.ntp import NTP
from dpkt.tcp import TCP
from dpkt.udp import UDP
from munch import Munch

from core.configuration.data import ConfigurationData
from core.lib.dpkt_parsers.arp_parser import ArpPacketParser
from core.lib.dpkt_parsers.dhcp_parser import DhcpPacketParser
from core.lib.dpkt_parsers.dns_parser import DnsPacketParser
from core.lib.dpkt_parsers.icmp_parser import Icmp6PacketParser, IcmpPacketParser
from core.lib.dpkt_parsers.ieee80211_parser import IEEE80211PacketParser
from core.lib.dpkt_parsers.ethernet_parser import EthernetFrameParser
from core.lib.dpkt_parsers.igmp_parser import IgmpPacketParser
from core.lib.dpkt_parsers.ip6_parser import Ip6PacketParser
from core.lib.dpkt_parsers.ip_parser import IpPacketParser
from core.lib.dpkt_parsers.layer4_parser import TcpPacketParser
from core.lib.dpkt_parsers.layer4_parser import UDPPacketParser
from core.lib.dpkt_parsers.llc_parser import LlcPacketParser
from core.lib.dpkt_parsers.mdns_parser import MdnsPacketParser
from core.lib.dpkt_parsers.ntp_parser import NtpPacketParser
from core.lib.dpkt_parsers.syn_parser import SynPacketParser
from core.lib.dpkt_parsers.upnp_parser import UpnpPacketParser
from core.lib.ip_utils import IpAddrUtils
from core.lib.mac_utils import MacAddressUtils
from core.models.packet_data import PacketData
from core.static.CONSTANTS import IEEE80211_PROTOCOL_NUMBER, UPNP_PORTS, MDNS_PORTS, DHCP_PORTS
from core.static.utils import StaticData


class DpktUtils:
    def __init__(self, config: ConfigurationData, static_data: StaticData = None):
        self.mac_utils = MacAddressUtils()
        self.ip_utils = IpAddrUtils()
        self.ether_type_data = StaticData.load_ether_types_data()
        self.config = config
        self.static_data = static_data or StaticData()

    def extract_data_from_eth_frame(self, eth_frame: Ethernet, packet_data: PacketData) -> PacketData:
        eth_frame_parser = EthernetFrameParser(config=self.config, static_data=self.static_data)
        eth_data = eth_frame_parser.extract_data(packet=eth_frame)
        packet_data = self.load_protocol_data_to_packet_data(eth_data, packet_data)

        return packet_data

    def extract_data_from_layer3_protocols(self, protocol: int, layer3_packet, packet_data: PacketData) -> PacketData:
        if protocol == dpkt.ethernet.ETH_TYPE_IP:               # IPv4 Packet
            packet_data = self.extract_data_from_ip_packet(ip_packet=layer3_packet, packet_data=packet_data)

        elif protocol == dpkt.ethernet.ETH_TYPE_IP6:            # IPv6 Packet
            packet_data = self.extract_data_from_ip6_packet(ip_packet=layer3_packet, packet_data=packet_data)

        elif protocol == dpkt.ethernet.ETH_TYPE_ARP:            # ARP packet
            packet_data = self.extract_and_load_data_from_arp_packet(arp_packet=layer3_packet, packet_data=packet_data)

        elif isinstance(layer3_packet, dpkt.llc.LLC):           # IEEE 802.3 Logical Link Control
            packet_data = self.extract_data_from_llc_packet(llc_packet=layer3_packet, packet_data=packet_data)

        elif protocol == IEEE80211_PROTOCOL_NUMBER:             # IEEE 802.1X Authentication
            packet_data = self.extract_data_from_80211_packet(packet_data_bytes=layer3_packet, packet_data=packet_data)

        else:                   # TODO: Handle other layer 3 protocols
            _protocol = self.ether_type_data.get(str(hex(protocol)[2:]))
            if _protocol is None:
                logging.warning('Unable to get protocol from ether_type (int): {}'.format(protocol))

        return packet_data

    def extract_data_from_ip_packet(self, ip_packet: IP, packet_data: PacketData) -> PacketData:
        ip_packet_parser = IpPacketParser(config=self.config, static_data=self.static_data)
        ip_packet_data = ip_packet_parser.extract_data(packet=ip_packet)
        packet_data = self.load_protocol_data_to_packet_data(ip_packet_data, packet_data)

        return packet_data

    def extract_data_from_ip6_packet(self, ip_packet: IP, packet_data: PacketData) -> PacketData:
        ip6_packet_parser = Ip6PacketParser(config=self.config)
        ip6_packet_data = ip6_packet_parser.extract_data(packet=ip_packet)
        packet_data = self.load_protocol_data_to_packet_data(ip6_packet_data, packet_data)

        return packet_data

    def extract_data_from_llc_packet(self, llc_packet: LLC, packet_data: PacketData) -> PacketData:
        llc_packet_parser = LlcPacketParser(config=self.config)
        llc_packet_data = llc_packet_parser.extract_data(llc_packet)
        packet_data = self.load_protocol_data_to_packet_data(llc_packet_data, packet_data)

        return packet_data

    def extract_data_from_80211_packet(self, packet_data_bytes: bytes, packet_data: PacketData) -> PacketData:
        packet = dpkt.ieee80211.IEEE80211(packet_data_bytes)
        ieee80211_packet_parser = IEEE80211PacketParser(config=self.config)
        ieee80211_packet_data = ieee80211_packet_parser.extract_data(packet)
        packet_data = self.load_protocol_data_to_packet_data(ieee80211_packet_data, packet_data)

        return packet_data

    def extract_data_from_layer4_protocols(self, protocol: int, layer4_packet, packet_data: PacketData) -> PacketData:
        if protocol == dpkt.ip.IP_PROTO_TCP:  # TCP packet
            packet_data = self.extract_data_from_tcp_packet(layer4_packet, packet_data,)

        elif protocol == dpkt.ip.IP_PROTO_UDP:  # UDP packet
            packet_data = self.extract_data_from_udp_packet(layer4_packet, packet_data)

        elif protocol == dpkt.ip.IP_PROTO_ICMP:  # ICMP packet
            packet_data = self.extract_and_load_data_from_icmp_packet(layer4_packet, packet_data)

        elif protocol == dpkt.ip.IP_PROTO_ICMP6:  # ICMPv6 packet
            packet_data = self.extract_and_load_data_from_icmp6_packet(layer4_packet, packet_data)

        elif protocol == dpkt.ip.IP_PROTO_IGMP:  # IGMP packet
            packet_data = self.extract_and_load_data_from_igmp_packet(layer4_packet, packet_data)

        else:
            logging.warning('Some other IP protocol. packet_type: {}'.format(type(layer4_packet)))

        return packet_data

    def extract_data_from_tcp_packet(self, tcp_packet: TCP, packet_data: PacketData) -> PacketData:
        tcp_packet_parser = TcpPacketParser(config=self.config, static_data=self.static_data)
        tcp_packet_data = tcp_packet_parser.extract_data(packet=tcp_packet)
        packet_data = self.load_protocol_data_to_packet_data(tcp_packet_data, packet_data)

        return packet_data

    def extract_and_load_data_from_icmp6_packet(self, icmp6_packet: ICMP6, packet_data: PacketData) -> PacketData:
        icmp6_packet_parser = Icmp6PacketParser(config=self.config)
        icmp6_packet_data = icmp6_packet_parser.extract_data(icmp6_packet)
        packet_data = self.load_protocol_data_to_packet_data(icmp6_packet_data, packet_data=packet_data)

        return packet_data

    def extract_and_load_data_from_icmp_packet(self, icmp_packet: ICMP, packet_data: PacketData) -> PacketData:
        icmp_packet_parser = IcmpPacketParser(config=self.config)
        icmp_packet_data = icmp_packet_parser.extract_data(icmp_packet)
        packet_data = self.load_protocol_data_to_packet_data(icmp_packet_data, packet_data=packet_data)

        return packet_data

    def extract_and_load_data_from_igmp_packet(self, igmp_packet: IGMP, packet_data: PacketData) -> PacketData:
        igmp_packet_parser = IgmpPacketParser(config=self.config)
        igmp_protocol_data = igmp_packet_parser.extract_data(igmp_packet)
        packet_data = self.load_protocol_data_to_packet_data(igmp_protocol_data, packet_data)

        return packet_data

    def extract_data_from_udp_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        udp_packet_parser = UDPPacketParser(config=self.config, static_data=self.static_data)
        udp_packet_data = udp_packet_parser.extract_data(packet=udp_packet)
        packet_data = self.load_protocol_data_to_packet_data(udp_packet_data, packet_data)

        return packet_data

    def extract_tcp_syn_signature(self, ip_packet: IP, packet_data: PacketData) -> PacketData:
        syn_packet_parser = SynPacketParser(config=self.config)
        syn_packet_data = syn_packet_parser.extract_data(ip_packet)
        packet_data = self.load_protocol_data_to_packet_data(syn_packet_data, packet_data)

        return packet_data

    def extract_data_from_layer7_protocols(self, layer4_packet, packet_data: PacketData) -> PacketData:
        if packet_data.src_port == 53 or packet_data.dst_port == 53:  # DNS Packet
            packet_data = self.extract_and_load_data_from_dns_packet(layer4_packet, packet_data)

        elif packet_data.src_port == 123 or packet_data.dst_port == 123:  # NTP packet
            packet_data = self.extract_and_load_data_from_ntp_packet(layer4_packet, packet_data)

        elif packet_data.src_port in UPNP_PORTS or packet_data.dst_port in UPNP_PORTS:  # UPnP packet
            return self.extract_and_load_data_from_upnp_packet(layer4_packet, packet_data)

        elif packet_data.src_port in MDNS_PORTS or packet_data.dst_port in MDNS_PORTS:  # mDNS packet
            return self.extract_and_load_data_from_mdns_packet(layer4_packet, packet_data)

        elif packet_data.src_port in DHCP_PORTS or packet_data.dst_port in DHCP_PORTS:  # DHCP packet
            return self.extract_and_load_data_from_dhcp_packet(udp_packet=layer4_packet, packet_data=packet_data)

        # TODO: Handle other application layer protocols.

        return packet_data

    def extract_and_load_data_from_ntp_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        ntp_packet_parser = NtpPacketParser(config=self.config)
        ntp_packet = ntp_packet_parser.load_ntp_packet_from_udp_packet(udp_packet)
        ntp_packet_data = ntp_packet_parser.extract_data(packet=ntp_packet)
        packet_data = self.load_protocol_data_to_packet_data(ntp_packet_data, packet_data)

        return packet_data

    def extract_and_load_data_from_dns_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        dns_packet_parser = DnsPacketParser(config=self.config)
        dns_packet = dns_packet_parser.load_dns_packet_from_udp_packet(udp_packet)
        dns_packet_data = dns_packet_parser.extract_data(packet=dns_packet)
        packet_data = self.load_protocol_data_to_packet_data(dns_packet_data, packet_data)

        return packet_data

    def extract_and_load_data_from_arp_packet(self, arp_packet: ARP, packet_data: PacketData) -> PacketData:
        arp_packet_parser = ArpPacketParser(config=self.config)
        arp_packet_data = arp_packet_parser.extract_data(packet=arp_packet)
        packet_data = self.load_protocol_data_to_packet_data(arp_packet_data, packet_data)

        return packet_data

    def extract_and_load_data_from_upnp_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        upnp_packet = UpnpPacketParser(config=self.config)
        upnp_protocol_data = upnp_packet.extract_data(udp_packet=udp_packet)
        packet_data = self.load_protocol_data_to_packet_data(upnp_protocol_data, packet_data=packet_data)

        return packet_data

    def extract_and_load_data_from_mdns_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        mdns_packet_parser = MdnsPacketParser(config=self.config)
        mdns_packet = MdnsPacketParser.load_mdns_packet_from_udp_packet(udp_packet)
        if mdns_packet is None:
            return packet_data

        mdns_protocol_data = mdns_packet_parser.extract_data(mdns_packet)
        packet_data = self.load_protocol_data_to_packet_data(mdns_protocol_data, packet_data)

        return packet_data

    def extract_and_load_data_from_dhcp_packet(self, udp_packet: UDP, packet_data: PacketData) -> PacketData:
        dhcp_packet_parser = DhcpPacketParser(config=self.config)
        dhcp_packet = dhcp_packet_parser.load_dhcp_from_udp_packet(udp_packet)
        dhcp_packet_data = dhcp_packet_parser.extract_data(dhcp_packet)
        packet_data = self.load_protocol_data_to_packet_data(dhcp_packet_data, packet_data)

        return packet_data

    def load_protocol_data_to_packet_data(
            self,
            protocol_data: Union[dict, Munch],
            packet_data: PacketData
    ) -> PacketData:
        if protocol_data is None or not isinstance(protocol_data, dict):
            logging.debug('Unable to load protocol data from `{}` object. <dict> expected'.format(type(protocol_data)))
            return packet_data

        for key, value in protocol_data.items():
            if packet_data.is_valid_value(value):  # If it is valid value, load it to packet data
                if hasattr(packet_data, key) and not callable(getattr(packet_data, key)):
                    setattr(packet_data, key, value)
                else:
                    logging.warning(
                        'Trying to set invalid or callable property `{}` in `{}` object'.format(key, type(packet_data))
                    )

        return packet_data
