import binascii
import logging
from typing import Union, Type, Optional

import dpkt
from dpkt import Packet
from dpkt.arp import ARP
from dpkt.dhcp import DHCP
from dpkt.dns import DNS
from dpkt.ethernet import Ethernet
from dpkt.icmp import ICMP
from dpkt.icmp6 import ICMP6
from dpkt.ieee80211 import IEEE80211
from dpkt.igmp import IGMP
from dpkt.ip import IP
from dpkt.ip6 import IP6
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
from core.lib.dpkt_parsers.mdns_unpacker import Mdns
from core.lib.dpkt_parsers.ntp_parser import NtpPacketParser
from core.lib.dpkt_parsers.syn_parser import SynPacketParser
from core.lib.dpkt_parsers.upnp_parser import UpnpPacketParser
from core.lib.dpkt_parsers.upnp_request import UpnpRequest
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

    def load_layer3_packet(self, eth_frame: Ethernet) -> Optional[Packet]:
        """
        Take an ethernet frame and parse its data as layer3 packet. Currently supported protocols are IPv4, IPv6, ARP,
        LLC, IEEE80211
        """
        if eth_frame.type == dpkt.ethernet.ETH_TYPE_IP:               # IPv4 Packet
            return IpPacketParser.load_ip_packet_from_ethernet_frame(eth_frame.data)

        elif eth_frame.type == dpkt.ethernet.ETH_TYPE_IP6:            # IPv6 Packet
            return IP6(eth_frame.data)

        elif eth_frame.type == dpkt.ethernet.ETH_TYPE_ARP:            # ARP packet
            return ARP(eth_frame.data)

        elif isinstance(eth_frame.data, dpkt.llc.LLC):           # IEEE 802.3 Logical Link Control
            return LLC(eth_frame.data)

        elif eth_frame.type == IEEE80211_PROTOCOL_NUMBER:             # IEEE 802.1X Authentication
            return IEEE80211(eth_frame.data)

        else:  # TODO: Handle other layer 3 protocols
            _protocol = self.ether_type_data.get(str(hex(eth_frame.type)[2:]))
            if _protocol is None:
                logging.warning('Unable to get protocol from ether_type (int): {}'.format(_protocol))

        return None

    def extract_data_from_layer3_packet(self, layer3_packet, packet_data: PacketData) -> PacketData:
        data = Munch()
        if isinstance(layer3_packet, IP):  # IPv4 Packet
            data = self.extract_data_from_ip4_packet(ip_packet=layer3_packet)

        elif isinstance(layer3_packet, IP6):  # IPv6 Packet
            data = self.extract_data_from_ip6_packet(ip6_packet=layer3_packet)

        elif isinstance(layer3_packet, ARP):  # ARP packet
            data = self.extract_data_from_arp_packet(arp_packet=layer3_packet)

        elif isinstance(layer3_packet, LLC):  # IEEE 802.3 Logical Link Control
            data = self.extract_data_from_llc_packet(llc_packet=layer3_packet)

        elif isinstance(layer3_packet, IEEE80211):  # IEEE 802.1X Authentication
            data = self.extract_data_from_80211_packet(layer3_packet)

        return self.load_protocol_data_to_packet_data(data, packet_data)

    def extract_data_from_ip4_packet(self, ip_packet: IP) -> Union[Munch, dict]:
        ip_packet_parser = IpPacketParser(config=self.config, static_data=self.static_data)
        return ip_packet_parser.extract_data(packet=ip_packet)

    def extract_data_from_ip6_packet(self, ip6_packet: IP6) -> Union[Munch, dict]:
        ip6_packet_parser = Ip6PacketParser(config=self.config)
        return ip6_packet_parser.extract_data(packet=ip6_packet)

    def extract_data_from_llc_packet(self, llc_packet: LLC) -> Union[Munch, dict]:
        llc_packet_parser = LlcPacketParser(config=self.config)
        return llc_packet_parser.extract_data(llc_packet)

    def extract_data_from_80211_packet(self, ieee80211_packet: IEEE80211) -> Union[Munch, dict]:
        ieee80211_packet_parser = IEEE80211PacketParser(config=self.config)
        return ieee80211_packet_parser.extract_data(ieee80211_packet)

    def extract_data_from_arp_packet(self, arp_packet: ARP) -> Union[Munch, dict]:
        arp_packet_parser = ArpPacketParser(config=self.config)
        return arp_packet_parser.extract_data(packet=arp_packet)

    def load_layer4_packet(self, layer3_packet: Packet) -> Optional[Packet]:
        if layer3_packet is None:
            return None
        print('*' * 80)
        print(layer3_packet)
        print('*' * 80)
        if layer3_packet.p == dpkt.ip.IP_PROTO_TCP:  # TCP packet
            return TCP(layer3_packet.data)

        elif layer3_packet.p == dpkt.ip.IP_PROTO_UDP:  # UDP packet
            return UDP(layer3_packet.data)

        elif layer3_packet.p == dpkt.ip.IP_PROTO_ICMP:  # ICMP packet
            return ICMP(layer3_packet.data)

        elif layer3_packet.p == dpkt.ip.IP_PROTO_ICMP6:  # ICMPv6 packet
            return ICMP6(layer3_packet.data)

        elif layer3_packet.p == dpkt.ip.IP_PROTO_IGMP:  # IGMP packet
            return IGMP(layer3_packet.data)

        else:
            logging.warning('Unidentified Protocol. Proto Num: {}, Type: {}'.format(
                layer3_packet.p, type(layer3_packet.data)
            ))

        return None

    def extract_data_from_layer4_packet(self, layer4_packet: Packet, packet_data: PacketData) -> PacketData:
        data = None
        if isinstance(layer4_packet, TCP):  # TCP packet
            data = self.extract_data_from_tcp_packet(layer4_packet)

        elif isinstance(layer4_packet, UDP):  # UDP packet
            data = self.extract_data_from_udp_packet(layer4_packet)

        elif isinstance(layer4_packet, ICMP):
            data = self.extract_data_from_icmp_packet(layer4_packet)

        elif isinstance(layer4_packet, ICMP6):
            data = self.extract_data_from_icmp6_packet(layer4_packet)

        elif isinstance(layer4_packet, IGMP):
            data = self.extract_data_from_igmp_packet(layer4_packet)

        return self.load_protocol_data_to_packet_data(data, packet_data)

    def extract_data_from_tcp_packet(self, tcp_packet: TCP) -> Union[Munch, dict]:
        tcp_packet_parser = TcpPacketParser(config=self.config, static_data=self.static_data)
        return tcp_packet_parser.extract_data(packet=tcp_packet)

    def extract_data_from_udp_packet(self, udp_packet: UDP) -> Union[Munch, dict]:
        udp_packet_parser = UDPPacketParser(config=self.config, static_data=self.static_data)
        return udp_packet_parser.extract_data(packet=udp_packet)

    def extract_data_from_icmp_packet(self, icmp_packet: ICMP) -> Union[Munch, dict]:
        icmp_packet_parser = IcmpPacketParser(config=self.config)
        return icmp_packet_parser.extract_data(icmp_packet)

    def extract_data_from_icmp6_packet(self, icmp6_packet: ICMP6) -> Union[Munch, dict]:
        icmp6_packet_parser = Icmp6PacketParser(config=self.config)
        return icmp6_packet_parser.extract_data(icmp6_packet)

    def extract_data_from_igmp_packet(self, igmp_packet: IGMP) -> Union[Munch, dict]:
        igmp_packet_parser = IgmpPacketParser(config=self.config)
        return igmp_packet_parser.extract_data(igmp_packet)

    def extract_tcp_syn_signature(self, ip_packet: IP, packet_data: PacketData) -> PacketData:
        syn_packet_parser = SynPacketParser(config=self.config)
        syn_packet_data = syn_packet_parser.extract_data(ip_packet)
        packet_data = self.load_protocol_data_to_packet_data(syn_packet_data, packet_data)

        return packet_data

    def load_layer7_packet(self, layer4_packet: Packet, packet_data: PacketData) -> Optional[Packet]:
        if isinstance(layer4_packet, UDP):
            if packet_data.src_port == 53 or packet_data.dst_port == 53:  # DNS packet
                return DnsPacketParser.load_dns_packet_from_udp_packet(layer4_packet)

            elif packet_data.src_port == 123 or packet_data.dst_port == 123:  # NTP packet
                return NtpPacketParser.load_ntp_packet_from_udp_packet(layer4_packet)

            elif packet_data.src_port in UPNP_PORTS or packet_data.dst_port in UPNP_PORTS:  # UPnP packet
                return UpnpPacketParser.load_upnp_packet_from_udp_packet(layer4_packet)

            elif packet_data.src_port in MDNS_PORTS or packet_data.dst_port in MDNS_PORTS:  # mDNS packet
                return MdnsPacketParser.load_mdns_packet_from_udp_packet(layer4_packet)

            elif packet_data.src_port in DHCP_PORTS or packet_data.dst_port in DHCP_PORTS:  # DHCP packet
                return DhcpPacketParser.load_dhcp_from_udp_packet(layer4_packet)

        return None

    def extract_data_from_layer7_packet(self, layer7_packet: Packet, packet_data: PacketData) -> PacketData:
        """Currently supported Layer 7 protocols are DHCP, UPNP, MDNS, DNS, NTP"""
        data = Munch()
        if isinstance(layer7_packet, DNS):  # DNS packet
            data = self.extract_data_from_dns_packet(layer7_packet)

        elif isinstance(layer7_packet, Mdns):  # mDNS packet
            data = self.extract_data_from_mdns_packet(layer7_packet)

        elif isinstance(layer7_packet, NTP):  # NTP packet
            data = self.extract_data_from_dns_packet(layer7_packet)

        elif isinstance(layer7_packet, UpnpRequest) or isinstance(layer7_packet, dpkt.http.Response):  # UPnP packet
            data = self.extract_data_from_dns_packet(layer7_packet)

        elif isinstance(layer7_packet, DHCP):  # DNS packet
            data = self.extract_data_from_dhcp_packet(layer7_packet)

        return self.load_protocol_data_to_packet_data(data, packet_data)

    def extract_data_from_ntp_packet(self, ntp_packet: NTP) -> Union[Munch, dict]:
        ntp_packet_parser = NtpPacketParser(config=self.config)
        return ntp_packet_parser.extract_data(ntp_packet)

    def extract_data_from_dns_packet(self, dns_packet: DNS) -> Union[Munch, dict]:
        dns_packet_parser = DnsPacketParser(config=self.config)
        return dns_packet_parser.extract_data(dns_packet)

    def extract_data_from_upnp_packet(self, upnp_packet: Union[UpnpRequest, dpkt.http.Response]) -> Union[Munch, dict]:
        upnp_packet_parser = UpnpPacketParser(config=self.config)
        return upnp_packet_parser.extract_data(upnp_packet)

    def extract_data_from_mdns_packet(self, mdns_packet: Mdns) -> Union[Munch, dict]:
        mdns_packet_parser = MdnsPacketParser(config=self.config)
        return mdns_packet_parser.extract_data(mdns_packet)

    def extract_data_from_dhcp_packet(self, dhcp_packet: DHCP) -> Union[Munch, dict]:
        dhcp_packet_parser = DhcpPacketParser(config=self.config)
        return dhcp_packet_parser.extract_data(dhcp_packet)

    def load_protocol_data_to_packet_data(
            self,
            protocol_data: Optional[Union[dict, Munch]],
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
