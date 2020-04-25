import logging
import random
import re
from typing import Optional

import binascii

from dpkt import compat_ord
from netaddr import EUI

from core.static.CONSTANTS import MAC_REGEX


class MacAddressUtils:
    def int2mac(self, mac_integer: int) -> Optional[str]:
        """
        Converts integer form of mac address to string form i.e.
        ('aa:bb:cc:dd:ee:ff')
        :param mac_integer: Integer representation of MAC address.
        :return: String representation of MAC address.
        """
        try:
            mac = str(EUI(mac_integer)).lower().replace('-', ':')
            if self.is_valid_mac(mac) is True:
                return mac

        except Exception as ex:
            logging.warning('Unable to convert mac (integer): {0} to string.Error: {1}'.format(mac_integer, ex))

        return None

    def hexadecimal_mac_to_readable_mac(self, mac_address: str) -> Optional[str]:
        """
        Converts MAC address from hex string to readable/printable string
        :param mac_address: Hex string for MAC (e.g. \x01\x02\x03\x04\x05\x06)
         :type: string
        :return mac: MAC address in printable format e.g. 00:01:02:03:04:05.
         :type: string
        """
        mac = ':'.join([binascii.hexlify(mac_address)[i:i + 2]
                        for i in range(0, len(binascii.hexlify(mac_address)), 2)])

        if self.is_valid_mac(mac) is True:
            return mac

        return None

    def convert_hexadecimal_mac_to_readable_mac(self, hexadecimal_mac: str) -> Optional[str]:
        """
        Convert mac address to readable string
        :param hexadecimal_mac: Hex MAC address (e.g. '\x01\x02\x03\x04\x05\x06')
          :type: hex string
        :return mac: printable/readable mac string
          :type: str
        """
        mac = ':'.join('%02x' % compat_ord(b) for b in hexadecimal_mac)
        if self.is_valid_mac(mac) is True:
            return mac

        return None

    def convert_string_mac_to_byte_array(self, mac_address: str) -> Optional[bytearray]:
        """
        Converts mac address string in hex format to byte array.
        :param mac_address: String mac address (semi-colon or dash separated
        :return: Byte array
        """
        if self.is_valid_mac(mac_address) is False:
            return None

        return bytearray.fromhex(mac_address.replace('-', '').replace(':', ''))

    def mac2int(self, mac_address: str) -> Optional[int]:
        """
        Converts MAC address string ('aa:bb:cc:dd:ee:ff') to integer representation.
        :param mac_address: MAC address in string form
        :return: Integer representation of MAC address string.
        """
        if self.is_valid_mac(mac_address):
            return int(EUI(mac_address.replace(':', '-')))

        logging.warning('Unable to convert ip: {} to integer representation')
        return None

    def is_valid_mac(self, mac_address: str) -> bool:
        """
        Checks if given string is a valid MAC address or not.
        :param mac_address: String
        :return: True if valid otherwise false
        """
        if not mac_address:
            return False
        if re.compile(MAC_REGEX, re.IGNORECASE).match(mac_address):
            return True

        return False

    def generate_random_mac(self) -> Optional[str]:
        """
        This function generates a random mac address.
        :return: mac_address: String
        """
        mac = ':'.join(map(lambda x: "%02x" % x, [random.randint(0x00, 0xff) for _ in range(6)]))
        if self.is_valid_mac(mac):
            return mac

    def is_mac_unique(self, mac_address: str = None) -> bool:
        """
        This function checks whether the given MAC addresses is genuinely unique and not one of the "well known" MAC
        addresses.
        :param mac_addr: MAC address to be checked.
        :return: True if given MAC address is not a well known MAC address,
        False otherwise.
        """
        from core.static.CONSTANTS import EXCLUDED_MACS, EXCLUDED_MACS_W_WILDCARDS

        if self.is_valid_mac(mac_address):
            return False

        mac_addr = mac_address.replace('-', ':').upper()
        # Check against specific MAC address
        if mac_addr in EXCLUDED_MACS:
            return False

        # Check against wildcards
        for wc_mac in EXCLUDED_MACS_W_WILDCARDS:
            if mac_addr[:len(wc_mac)] == wc_mac:
                return False

        return True
    
