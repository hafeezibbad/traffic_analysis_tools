# https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml

ICMP6_CODE_DESTINATION_UNREACHABLE = {
    0: "no router to destination",
    1: "communication with destination administratively prohibited",
    2: "beyond scope of source address",                # [RFC4443]
    3: "address unreachable",
    4: "port unreachable",
    5: "source address failed ingree/egress policy",    # [RFC4443]
    6: "reject router to destination",                  # [RFC4443]
    7: "Error in Source Routing Header",                # [RFC6550][RFC6554]
}

ICMP6_CODE_PACKET_TOO_BIG = {
    0: "no error"
}

ICMP6_CODE_TIME_EXCEEDED = {
    0: "hope limit exceeded in transit",
    1: "fragment reassembly time exceeded"
}

ICMP6_CODE_PARAMETER_PROBLEM = {
    0: "erroneous header field encountered",
    1: "unrecognized Next Header type encountered",
    2: "unrecognized IPv6 option encountered",
    3: "IPv6 First Fragment has incomplete IPv6 Header Chain",          # [RFC7112]
    4: "SR Upper-layer Header Error"
}

ICMP6_CODE_ECHO_REQUEST = {
    0: "no error"
}

ICMP6_CODE_ROUTER_RENUMBERING = {
    0: "Router renumbering Command",
    1: "Router Renumbering Result",
    255: "Sequence Number Reset"
}

ICMP6_CODE_ICMP_NODE_INFORMATION_QUERY = {
    0: "The Data field contains an IPv6 address which is the Subject of this Query.",               # [RFC4620]
    1: "The Data field contains a name which is the Subject of this Query, or is empty, "
       "as in the case of a NOOP.",                                                                 # [RFC4620]
    2: "The Data field contains an IPv4 address which is the Subject of this Query."                # [RFC4620]
}

ICMP6_CODE_ICMP_NODE_INFORMATION_RESPONSE = {
    0: "A successful reply. The Reply Data field may or may not be empty.",                         # [RFC4620]
    1: "The Responder refuses to supply the answer. The Reply Data field will be empty.",           # [RFC4620]
    2: "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty"     # [RFC4620]
}

ICMP6_CODE_DUPLICATION_ADDR_REQUEST_CODE_SUFFIX = {
    0: "DAR message",                                   # [RFC6775]
    1: "EDAR message with 64-bit ROVR field",           # [RFC8505]
    2: "EDAR message with 128-bit ROVR field",          # [RFC8505]
    3: "EDAR message with 192-bit ROVR field",          # [RFC8505]
    4: "EDAR message with 256-bit ROVR field",          # [RFC8505]
}

ICMP6_CODE_DUPLICATION_ADDR_CONFIRMATION_CODE_SUFFIX = {
    0: "DAC message",                                   # [RFC6775]
    1: "EDAC message with 64-bit ROVR field",           # [RFC8505]
    2: "EDAC message with 128-bit ROVR field",          # [RFC8505]
    3: "EDAC message with 192-bit ROVR field",          # [RFC8505]
    4: "EDAC message with 256-bit ROVR field",          # [RFC8505]
}

ICMP6_CODE_EXTENDED_ECHO_REQUEST = {
    0: "No Error"                                       # [RFC83]
}

ICMP6_CODE_EXTENDED_ECHO_REPLY = {
    0: "No Error",                                      # [RFC8335]
    1: "Malformed Query",                               # [RFC8335]
    2: "No Such Interface",                             # [RFC8335]
    3: "NO Such Table Entry",                           # [RFC8335]
    4: "Multiple Interfaces Satisfy Query",             # [RFC8335]
}

ICMP_CODE_FMIPv6_MESSAGE_TYPES = {
    0: "Reserved",                                          # [RFC5568]
    1: "Reserved",                                          # [RFC5568]
    2: "RtSolPr",                                           # [RFC5568]
    3: "PrRtAdv",                                           # [RFC5568]
    4: "HI - Deprecated (Unavailable for Assignment)",      # [RFC5568]
    5: "HAck - Deprecated (Unavailable for Assignment)",    # [RFC5568]
}

ICMP6_CODE_TRUST_ANCHOR_OPTION = {
    0: "Reserved",                                          # [RFC6495]
    1: "DER Encoded X.501 Name",                            # [RFC3971]
    2: "FQDN",                                              # [RFC3971]
    3: "SHA-1 Subject Key Identifier (SKI)",                # [RFC6495]
    4: "SHA-224 Subject Key Identifier (SKI)",              # [RFC6495]
    5: "SHA-256 Subject Key Identifier (SKI)",              # [RFC6495]
    6: "SHA-384 Subject Key Identifier (SKI)",              # [RFC6495]
    7: "SHA-512 Subject Key Identifier (SKI)",              # [RFC6495]
    # 8-252: "Unassigned",
    253: "Reserved for Experimental Use",                   # [RFC6495]
    254: "Reserved for Experimental Use",                   # [RFC6495]
    255: "Reserved",                                        # [RFC6495]
}

ICMP6_CODE_CERTIFICATE_OPTION = {
    0: "Reserved",
    1: "X.509v3 Certificate",                               # [RFC3971]
    # 2-255: "Unassigned"
}

ICMP6_CODE_HANDOVER_ASSIST_INFO_TYPE = {
    0: "Reserved",                                          # [RFC5271]
    1: "AN ID",                                             # [RFC5271]
    2: "Section ID",                                        # [RFC5271]
    # 3-255: "Unassigned"
}

ICMP6_CODE_MOBILE_NODE_IDENTIFIER_OPTION = {
    0: "Reserved",                                          # [RFC5271]
    1: "NAI",                                               # [RFC5271]
    2: "IMSI",                                              # [RFC5271]
    # 3-255: "Unassigned"
}

ICMP6_TYPES = {
    0: "Reserved",  #
    1: ICMP6_CODE_DESTINATION_UNREACHABLE,                  # [RFC4443]
    2: ICMP6_CODE_PACKET_TOO_BIG,                           # [RFC4443]
    3: ICMP6_CODE_TIME_EXCEEDED,                            # [RFC4443]
    4: ICMP6_CODE_PARAMETER_PROBLEM,                        # [RFC4443]
    15: ICMP6_CODE_TRUST_ANCHOR_OPTION,
    16: ICMP6_CODE_CERTIFICATE_OPTION,
    29: ICMP6_CODE_HANDOVER_ASSIST_INFO_TYPE,
    30: ICMP6_CODE_MOBILE_NODE_IDENTIFIER_OPTION,
    # 5 - 99: "Unassigned",
    100: "Private experimentation",                         # [RFC4443]
    101: "Private experimentation",                         # [RFC4443]
    # 102 - 126: "Unassigned",
    127: "Reserved for expansion of ICMPv6 error messages",     # [RFC4443]
    128: ICMP6_CODE_ECHO_REQUEST,                               # [RFC4443]
    129: "Echo Reply",                                          # [RFC4443]
    130: "Multicast Listener Query",                            # [RFC2710]
    131: "Multicast Listener Report",                           # [RFC2710]
    132: "Multicast Listener Done",                             # [RFC2710]
    133: "Router Solicitation",                                 # [RFC4861]
    134: "Router Advertisement",                                # [RFC4861]
    135: "Neighbor Solicitation",                               # [RFC4861]
    136: "Neighbor Advertisement",                              # [RFC4861]
    137: "Redirect Message",                                    # [RFC4861]
    138: ICMP6_CODE_ROUTER_RENUMBERING,                         # [RFC2894]
    139: ICMP6_CODE_ICMP_NODE_INFORMATION_QUERY,                # [RFC4620]
    140: "ICMP Node Information Response",                      # [RFC4620]
    141: "Inverse Neighbor Discovery Solicitation Message",     # [RFC3122]
    142: "Inverse Neighbor Discovery Advertisement Message",    # [RFC3122]
    143: "Version 2 Multicast Listener Report",                 # [RFC3810]
    144: "Home Agent Address Discovery Request Message",        # [RFC6275]
    145: "Home Agent Address Discovery Reply Message",          # [RFC6275]
    146: "Mobile Prefix Solicitation",                          # [RFC6275]
    147: "Mobile Prefix Advertisement",                         # [RFC6275]
    148: "Certification Path Solicitation Message",             # [RFC3971]
    149: "Certification Path Advertisement Message",            # [RFC3971]
    150: "ICMP messages utilized by experimental mobility protocols such as Seamoby",   # [RFC4065]
    151: "Multicast Router Advertisement",                      # [RFC4286]
    152: "Multicast Router Solicitation",                       # [RFC4286]
    153: "Multicast Router Termination",                        # [RFC4286]
    154: ICMP_CODE_FMIPv6_MESSAGE_TYPES,                        # [RFC5568]
    155: "RPL Control Message",                                 # [RFC6550]
    156: "ILNPv6 Locator Update Message",                       # [RFC6743]
    157: ICMP6_CODE_DUPLICATION_ADDR_REQUEST_CODE_SUFFIX,       # [RFC6775]
    158: ICMP6_CODE_DUPLICATION_ADDR_CONFIRMATION_CODE_SUFFIX,  # [RFC6775]
    159: "MPL Control Message",                                 # [RFC7731]
    160: ICMP6_CODE_EXTENDED_ECHO_REQUEST,                      # [RFC8335]
    161: ICMP6_CODE_EXTENDED_ECHO_REPLY,                        # [RFC8335]
    # 162 - 199: "Unassigned",
    200: "Private experimentation",                             # [RFC4443]
    201: "Private experimentation",                             # [RFC4443]
    255: "Reserved for expansion of ICMPv6 informational messages"                      # [RFC4443]
}
