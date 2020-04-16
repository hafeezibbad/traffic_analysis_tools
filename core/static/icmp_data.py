# http://www.iana.org/assignments/icmp-parameters

ICMP_CODE_ECHO_REPLY = {                        # [RFC792][RFC2780]
    0: "No Code"
}

ICMP_CODE_SOURCE_QUENCH = {
    0: "No Code"                                    # Deprecated
}

ICMP_CODES_DEST_UNREACHABLE = {                 # [RFC792][RFC2780]
    0: "Net Unreachable",                                                                   # [RFC792]
    1: "Host Unreachable",                                                                  # [RFC792]
    2: "Protocol Unreachable",                                                              # [RFC792]
    3: "Port Unreachable",                                                                  # [RFC792]
    4: "Fragmentation Needed and Don't Fragment was Set",                                   # [RFC792]
    5: "Source Route Failed",                                                               # [RFC792]
    6: "Destination Network Unknown",                                                       # [RFC1122]
    7: "Destination Host Unknown",                                                          # [RFC1122]
    8: "Source Host Isolated",                                                              # [RFC1122]
    9: "Communication with Destination Network is Administratively Prohibited",             # [RFC1122]
    10: "Communication with Destination Host isAdministratively Prohibited",                # [RFC1122]
    11: "Destination Network Unreachable for Type of Service",                              # [RFC1122]
    12: "Destination Host Unreachable for Type of Service",                                 # [RFC1122]
    13: "Communication Administratively Prohibited",                                        # [RFC1812]
    14: "Host Precedence Violation",                                                        # [RFC1812]
    15: "Precedence cutoff in effect",                                                      # [RFC1812]
}

ICMP_CODES_REDIRECT = {
    0: "Redirect Datagram for the Network (or subnet)",
    1: "Redirect Datagram for the Host",
    2: "Redirect Datagram for the Type of Service and Network",
    3: "Redirect Datagram for the Type of Service and Host"
}

ICMP_CODE_ALT_HOST_ADDR = {
    0: "No Code"                                    # Deprecated
}

ICMP_CODES_ECHO = {
    0: "No Code"                                    # Deprecated
}

ICMP_CODES_ROUTER_ADVERTISEMENT = {
    0: "Normal router advertisement",
    16: "Does not router common traffic"
}

ICMP_CODES_ROUTER_SELECTION = {
    0: "No Code"
}

ICMP_CODES_TIME_EXCEEDED = {
    0: "No Code",
    1: "Fragment Reasssembly Time Exceeded"
}

ICMP_CODES_PARAMETER_PROBLEM = {
    0: "Pointer indicates the error",
    1: "Missing a Required Option",                                 # [RFC1108]
    2: "Bad Length"
}

ICMP_CODES_TIMESTAMP = {                        # [RFC792][RFC2780]
    0: "No Code"
}

ICMP_CODES_TIMESTAMP_REPLY = {                  # [RFC792][RFC2780]
    0: "No Code"
}

ICMP_CODES_INFORMATION_REQUEST = {
    0: "No Code"
}

ICMP_CODES_INFORMATION_REPLY = {
    0: "No Code"                    # Depreacted
}

ICMP_CODES_ADDR_MASK_REQUEST = {
    0: "No Code"                    # Depreacted
}


ICMP_CODES_ADDR_MASK_REPLY = {
    0: "No Code"                    # Depreacted
}

ICMP_CODES_PHOTURIS = {
    0: "Bad SPI",
    1: "Authentication Failed",
    2: "Decompression Failed",
    3: "Decryption Failed",
    4: "Need Authentication",
    5: "Need Authorization"
}

ICMP_CODES_EXTENDED_ECHO_REQUEST = {
    0: "No Error",                                  # [RFC 8335]
}


ICMP_CODES_EXTENDED_ECHO_REPLY = {
    0: "No Error",
    1: "Malformed Query",
    2: "No Such Interface",
    3: "No Such Table Entry",
    4: "Multiple Interfaces Satisfy Query"
}

UNASSIGNED = None

ICMP_TYPES = {
    0: ICMP_CODE_ECHO_REPLY,                                # [RFC792]
    1: "Unassigned",
    2: "Unassigned",
    3: ICMP_CODES_DEST_UNREACHABLE,                         # [RFC792]
    4: ICMP_CODE_SOURCE_QUENCH,                             # [RFC792][RFC6633]
    5: ICMP_CODES_REDIRECT,                                 # [RFC792][RFC2780]
    6: ICMP_CODE_ALT_HOST_ADDR,                             # (Deprecated) [JBP][RFC6918]
    7: "Unassigned",
    8: ICMP_CODES_ECHO,                                     # (Deprecated) [RFC792][RFC2780]
    9: ICMP_CODES_ROUTER_ADVERTISEMENT,                     # [RFC1256][RFC2780]
    10: ICMP_CODES_ROUTER_SELECTION,                        # [RFC1256][RFC2780]
    11: ICMP_CODES_TIME_EXCEEDED,                           # [RFC792][RFC2780]
    12: ICMP_CODES_PARAMETER_PROBLEM,                       # [RFC792][RFC2780]
    13: ICMP_CODES_TIMESTAMP,                               # [RFC792][RFC2780]
    14: ICMP_CODES_TIMESTAMP_REPLY,                         # [RFC792][RFC2780]
    15: ICMP_CODES_INFORMATION_REQUEST,                     # (Deprecated) [RFC792][RFC6918]
    16: ICMP_CODES_INFORMATION_REPLY,                       # (Deprecated) [RFC792][RFC6918]
    17: ICMP_CODES_ADDR_MASK_REQUEST,                       # (Deprecated) [RFC950][RFC6918]
    18: ICMP_CODES_ADDR_MASK_REPLY,                         # (Deprecated) [RFC950][RFC6918]
    19: "Reserved (for Security)",                          # [Solo]
    20: "Reserved (for Robustness Experiment)",             # [ZSu]
    21: "Reserved (for Robustness Experiment)",             # [ZSu]
    22: "Reserved (for Robustness Experiment)",             # [ZSu]
    23: "Reserved (for Robustness Experiment)",             # [ZSu]
    24: "Reserved (for Robustness Experiment)",             # [ZSu]
    25: "Reserved (for Robustness Experiment)",             # [ZSu]
    26: "Reserved (for Robustness Experiment)",             # [ZSu]
    27: " Reserved (for Robustness Experiment)",            # [ZSu]
    28: "Reserved (for Robustness Experiment)",             # [ZSu]
    29: "Reserved (for Robustness Experiment)",             # [ZSu]
    30: "Traceroute (Deprecated)",                          # [RFC1393][RFC6918]
    31: "Datagram Conversion Error (Deprecated)",           # [RFC1475][RFC6918]
    32: "Mobile Host Redirect (Deprecated)",                # [David_Johnson][RFC6918]
    33: "IPv6 Where-Are-You (Deprecated)",                  # [Simpson][RFC6918]
    34: "IPv6 I-Am-Here (Deprecated)",                      # [Simpson][RFC6918]
    35: "Mobile Registration Request (Deprecated)",         # [Simpson][RFC6918]
    36: "Mobile Registration Reply (Deprecated)",           # [Simpson][RFC6918]
    37: "Domain Name Request (Deprecated)",                 # [RFC1788][RFC6918]
    38: "Domain Name Reply (Deprecated)",                   # [RFC1788][RFC6918]
    39: "SKIP (Deprecated)",                                # [Markson][RFC6918]
    40: ICMP_CODES_PHOTURIS,                                # [RFC2521]
    41: "ICMP messages utilized by experimental mobility protocols such as Seamoby",  # [RFC4065]
    42: ICMP_CODES_EXTENDED_ECHO_REQUEST,                   # [RFC8335]
    43: ICMP_CODES_EXTENDED_ECHO_REPLY,                     # [RFC8335]
    # 44-252: "Unassigned",
    253: "RFC3692-style Experiment 1",                      # [RFC4727]
    254: "RFC3692-style Experiment 2",                      # [RFC4727]
    255: "Reserved"                                         # [JBP]
}
