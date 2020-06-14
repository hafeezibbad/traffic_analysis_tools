"""Constants used in application."""
# pylint: disable=anomalous-backslash-in-string
# pylint: disable=invalid-name
import os

STATICS_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
IP_PROTOCOLS_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'ip_protocol_data.json')
IP_OPTIONS_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'ip_options_data.json')
ETHER_TYPES_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'ethertype_data.json')
LAYER4_PORTS_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'layer4_port_data.json')
TCP_FLAGS_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'tcp_flags_data.json')
MANUF_DATA_FILE_PATH = os.path.join(STATICS_DIR_PATH, 'manuf')
IEEE80211_PROTOCOL_NUMBER = 34958
EXCLUDED_MACS = [
    'FF:FF:FF:FF:FF:FF',       # Broadcast
    '01:00:0C:CC:CC:CC',       # CISCO discovery protocol
    '01:00:0C:CC:CC:CD',       # CISCO shared spanning tree proto
    '01:80:C2:00:00:00',       # Spanning tree protocol
    '01:80:C2:00:00:00',       # LLDP
    '01:80:C2:00:00:03',       # LLDP
    '01:80:C2:00:00:0E',       # LLDP
    '01:80:C2:00:00:08',       # IEEE 802.1ad
    '01:80:C2:00:00:01',       # IEEE 802.3x
    '01:80:C2:00:00:02',       # IEEE 802.3h
    '01:80:C2:00:00:30',       # IEEE 802.1ag
    '01:80:C2:00:00:3F',       # IEEE 802.1ag
    '01:1B-19-00:00:00',       # Precision Time Protocol
    '01:80:C2:00:00:0E',       # Precision Time Protocol
]
EXCLUDED_MACS_W_WILDCARDS = [
    '01:00:5E',             # IPv4 Multi-cast DNS
    '01:0C:CD:04',          # Multi-cast sampled values
    '01:0C:CD:02',          # GSSE (IEC 61850 8-1)
    '01:0C:CD:01',          # IEC 61850-8-1 GOOSE Type 1/1A
    '33:33',                # IPv6 Multi-cast
    '01:80:C2:00:00:3',     # IEEE 802.1ag
]
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DHCP_PORTS = [68, 67]
UPNP_PORTS = [1900, 60300]
MDNS_PORTS = [5353, 60301]
HTTP_METHODS = (
    'GET',
    'PUT',
    'ICY',
    'COPY',
    'HEAD',
    'LOCK',
    'MOVE',
    'POLL',
    'POST',
    'BCOPY',
    'BMOVE',
    'MKCOL',
    'TRACE',
    'LABEL',
    'MERGE',
    'DELETE',
    'SEARCH',
    'UNLOCK',
    'REPORT',
    'UPDATE',
    'NOTIFY',
    'BDELETE',
    'CONNECT',
    'OPTIONS',
    'CHECKIN',
    'PROPFIND',
    'CHECKOUT',
    'CCM_POST',
    'SUBSCRIBE',
    'PROPPATCH',
    'BPROPFIND',
    'BPROPPATCH',
    'UNCHECKOUT',
    'MKACTIVITY',
    'MKWORKSPACE',
    'UNSUBSCRIBE',
    'RPC_CONNECT',
    'VERSION-CONTROL',
    'BASELINE-CONTROL'
)
