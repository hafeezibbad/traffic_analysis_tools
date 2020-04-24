from typing import Optional

from core.models.common import Model


class PacketData(Model):
    timestamp: float = 0
    ref_time: float = 0
    size: float = 0  # Bytes
    outgoing: bool = False
    # Layer 2: Data link layer
    src_mac: Optional[str]
    dst_mac: Optional[str]
    eth_type: Optional[str]
    eth_frame_payload_size: Optional[int]  # Bytes
    layer3_undecoded_data: Optional[str]  # bytes object containing ethernet frame data for packets which are not parsed
    # Layer 3: Network layer
    src_ip: Optional[str]
    dst_ip: Optional[str]
    ip_tos: Optional[int]
    ip_ttl: Optional[int]
    ip_opts: Optional[int]
    ip_proto: Optional[int]
    ip_payload_size: Optional[int]
    ip6_nxt_hdr: Optional[str]
    ip_do_not_fragment: bool = True
    ip_more_fragment: bool = False
    # Layer 3: IEEE-8-1211.Auth
    ieee80211_version: Optional[int]
    ieee80211_payload_size: Optional[int]
    # Layer 4: ICMP packets
    icmp_type: Optional[int]
    icmp_code: Optional[int]
    icmp_message: Optional[str]
    # Layer 4: IGMP Packets
    igmp_type: Optional[int]   # 3: Change to Include Mode (Leave group), 4: Change to exclude mode (Join Group)
    igmp_addr: Optional[str]    # IGMP Multicast address
    # Layer 4: Transport layer
    src_port: Optional[int]
    dst_port: Optional[int]
    layer4_payload_size: Optional[int]
    data_from_fragment: Optional[str]
    # Layer 4: TCP flags
    tcp_fin_flag: bool = False
    tcp_syn_flag: bool = False
    tcp_rst_flag: bool = False
    tcp_psh_flag: bool = False
    tcp_ack_flag: bool = False
    tcp_urg_flag: bool = False
    tcp_ece_flag: bool = False
    tcp_cwr_flag: bool = False
    # TCP Syn packet data
    syn_signature: Optional[str]
    client_os: Optional[str]
    # Layer 4: NAT-PMP data
    natpmp_version: Optional[int]  # 0: NAT-PMP, 1: PCP (recommended over NAT-PMP)
    natpmp_opcode: Optional[int]
    natpmp_reserved: Optional[int]
    natpmp_result: Optional[int]
    natpmp_sssoe: Optional[int]
    natpmp_lifetime: Optional[int]
    natpmp_external_ip: Optional[str]
    natpmp_internal_port: Optional[int]
    natpmp_external_port: Optional[int]
    # Layer 7: Application layer
    layer7_proto: Optional[int]
    layer7_proto_name: Optional[str]
    dhcp_opts: Optional[str]
    payload_size: Optional[int]
    # Layer 7: DNS queries
    dns_type: Optional[int]
    dns_rcode: Optional[int]
    dns_op: Optional[int]
    dns_query_domain: Optional[str]
    dns_query_type: Optional[int]
    dns_query_cls: Optional[int]
    dns_query_multiple_domains: bool = False
    # Layer 7: DNS answers
    dns_ans_type: Optional[str]
    dns_ans_cname: Optional[str]
    dns_ans_cname_ttl: Optional[int]
    dns_ans_name: Optional[str]
    dns_ans_ip: Optional[str]
    dns_ans_ttl: Optional[str]
    # Layer 7: ARP data
    arp_request_src: Optional[int]   # '-1': client, '1': server
    arp_src_mac: Optional[str]
    arp_src_ip: Optional[str]
    arp_dst_mac: Optional[str]
    arp_dst_ip: Optional[str]
    # Layer 7: NTP
    ntp_mode: Optional[int]   # -1= client, 1= Server
    ntp_interval: Optional[int]   # Polling interval choice 5 (means 32 seconds polling interval)
    ntp_reference_id: Optional[str]
    ntp_stratum: Optional[int]   # 1: primary reference, 2: secondary reference, Layer 7: DHCP
    dhcp_fingerprint: Optional[str]
    dhcp_vendor: Optional[str]
    dhcp_hostname: Optional[str]
    # Layer 7: mDNS
    mdns_packet_type: Optional[int]   # 1: Query, 2: Response
    mdns_hostname: Optional[str]
    mdns_services: Optional[str]
    # Layer 7: UPnP message, SSDP Protocol
    upnp_packet_type: Optional[int]   # 1: Notify Request 2: M-SEARCH request, 3: Response
    upnp_location: Optional[str]   # URL where an XML formatted file can be downloaded
    upnp_server: Optional[str]
    upnp_cache: Optional[int]    # Cache-Control
    upnp_uns: Optional[str]
    upnp_nt: Optional[str]
    upnp_nts: Optional[str]   # Message Type
    upnp_host: Optional[str]
    upnp_st: Optional[str]
    upnp_man: Optional[str]
    upnp_mx: Optional[str]

    @staticmethod
    def is_valid_value(value) -> bool:
        if value is None:
            return False

        if isinstance(value, int) and value >= 0:
            return True

        if isinstance(value, str) and value != '':
            return True

        if value:  # Type dict, list, tuple, etc.
            return True

        return False

    def to_csv_string(self, delimiter=','):
        """The sequence should be similar to packet_data_file_headers"""
        values = []
        for attr in [
            self.timestamp,
            self.ref_time,
            self.size,
            self.outgoing,
            # Layer 2: Data link layer
            self.src_mac,
            self.dst_mac,
            self.eth_type,
            self.eth_frame_payload_size,
            self.layer3_undecoded_data,
            # Layer 3: Network layer
            self.src_ip,
            self.dst_ip,
            self.ip_tos,
            self.ip_ttl,
            self.ip_opts,
            self.ip_proto,
            self.ip_payload_size,
            self.ip6_nxt_hdr,
            self.ip_do_not_fragment,
            self.ip_more_fragment,
            # Layer 3: IEEE-8-1211.Auth
            self.ieee80211_version,
            self.ieee80211_payload_size,
            # Layer 4: ICMP packets
            self.icmp_type,
            self.icmp_code,
            self.icmp_message,
            # Layer 4: IGMP Packets
            self.igmp_type,
            self.igmp_addr,
            # Layer 4: Transport layer
            self.src_port,
            self.dst_port,
            self.layer4_payload_size,
            self.data_from_fragment,
            # Layer 4: TCP flags
            self.tcp_fin_flag,
            self.tcp_syn_flag,
            self.tcp_rst_flag,
            self.tcp_psh_flag,
            self.tcp_ack_flag,
            self.tcp_urg_flag,
            self.tcp_ece_flag,
            self.tcp_cwr_flag,
            # TCP Syn packet data
            self.syn_signature,
            self.client_os,
            # Layer 4: NAT-PMP data
            self.natpmp_version,
            self.natpmp_opcode,
            self.natpmp_reserved,
            self.natpmp_result,
            self.natpmp_sssoe,
            self.natpmp_lifetime,
            self.natpmp_external_ip,
            self.natpmp_internal_port,
            self.natpmp_external_port,
            # Layer 7: Application layer
            self.layer7_proto,
            self.layer7_proto_name,
            self.dhcp_opts,
            self.payload_size,
            # Layer 7: DNS queries
            self.dns_type,
            self.dns_rcode,
            self.dns_op,
            self.dns_query_domain,
            self.dns_query_type,
            self.dns_query_cls,
            self.dns_query_multiple_domains,
            # Layer 7: DNS answers
            self.dns_ans_type,
            self.dns_ans_cname,
            self.dns_ans_cname_ttl,
            self.dns_ans_name,
            self.dns_ans_ip,
            self.dns_ans_ttl,
            # Layer 7: ARP data
            self.arp_request_src,
            self.arp_src_mac,
            self.arp_src_ip,
            self.arp_dst_mac,
            self.arp_dst_ip,
            # Layer 7: NTP
            self.ntp_mode,
            self.ntp_interval,
            self.ntp_reference_id,
            self.ntp_stratum,
            # Layer 7: DHCP
            self.dhcp_fingerprint,
            self.dhcp_vendor,
            self.dhcp_hostname,
            # Layer 7: mDNS
            self.mdns_packet_type,
            self.mdns_hostname,
            self.mdns_services,
            # Layer 7: UPnP message, SSDP Protocol
            self.upnp_packet_type,
            self.upnp_location,
            self.upnp_server,
            self.upnp_cache,
            self.upnp_uns,
            self.upnp_nt,
            self.upnp_nts,
            self.upnp_host,
            self.upnp_st,
            self.upnp_man,
            self.upnp_mx
        ]:
            if attr is not None and attr is not False:
                values.append(str(attr))
            else:
                values.append('')

        return delimiter.join(values)

    @staticmethod
    def packet_data_file_headers(delimiter: str = ','):
        """The sequence of headers should be same as sequence of items in to_csv_string()"""
        return delimiter.join([str(attr) for attr in [
            "timestamp",
            "ref_time",
            "size",
            "outgoing",
            # Layer 2: Data link layer
            "src_mac",
            "dst_mac",
            "eth_type",
            "eth_frame_payload_size",
            "layer3_undecoded_data",
            # Layer 3: Network layer
            "src_ip",
            "dst_ip",
            "ip_tos",
            "ip_ttl",
            "ip_opts",
            "ip_proto",
            "ip_payload_size",
            "ip6_nxt_hdr",
            "ip_do_not_fragment",
            "ip_more_fragment",
            # Layer 3: IEEE-80211.Auth
            "ieee80211_version",
            "ieee80211_payload_size",
            # Layer 4: ICMP packets
            "icmp_type",
            "icmp_code",
            "icmp_message",
            # Layer 4: IGMP Packets
            "igmp_type",
            "igmp_addr",
            # Layer 4: Transport layer
            "src_port",
            "dst_port",
            "layer4_payload_size",
            "data_from_fragment",
            # Layer 4: TCP flags
            "tcp_fin_flag",
            "tcp_syn_flag",
            "tcp_rst_flag",
            "tcp_psh_flag",
            "tcp_ack_flag",
            "tcp_urg_flag",
            "tcp_ece_flag",
            "tcp_cwr_flag",
            # TCP Syn packet data
            "syn_signature",
            "client_os",
            # Layer 4: NAT-PMP data
            "natpmp_version",
            "natpmp_opcode",
            "natpmp_reserved",
            "natpmp_result",
            "natpmp_sssoe",
            "natpmp_lifetime",
            "natpmp_external_ip",
            "natpmp_internal_port",
            "natpmp_external_port",
            # Layer 7: Application layer
            "layer7_proto",
            "layer7_proto_name",
            "dhcp_opts",
            "payload_size",
            # Layer 7: DNS queries
            "dns_type",
            "dns_rcode",
            "dns_op",
            "dns_query_domain",
            "dns_query_type",
            "dns_query_cls",
            "dns_query_multiple_domains",
            # Layer 7: DNS answers
            "dns_ans_type",
            "dns_ans_cname",
            "dns_ans_cname_ttl",
            "dns_ans_name",
            "dns_ans_ip",
            "dns_ans_ttl",
            # Layer 7: ARP data
            "arp_request_src",
            "arp_src_mac",
            "arp_src_ip",
            "arp_dst_mac",
            "arp_dst_ip",
            # Layer 7: NTP
            "ntp_mode",
            "ntp_interval",
            "ntp_reference_id",
            "ntp_stratum",
            # Layer 7: DHCP
            "dhcp_fingerprint",
            "dhcp_vendor",
            "dhcp_hostname",
            # Layer 7: mDNS
            "mdns_packet_type",
            "mdns_hostname",
            "mdns_services",
            # Layer 7: UPnP message, SSDP Protocol
            "upnp_packet_type",  # 1: HTTP Request, 2: HTTP Response
            "upnp_location",
            "upnp_server",
            "upnp_cache",
            "upnp_uns",
            "upnp_nt",
            "upnp_nts",
            "upnp_host",
            "upnp_st",
            "upnp_man",
            "upnp_mx"
        ]])
