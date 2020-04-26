import logging
import random
import re
import socket
import struct
from typing import Optional
from urllib.parse import urlparse

from netaddr import IPAddress

from core.static.CONSTANTS import IPv4_REGEX, IPv6_REGEX


class IpAddrUtils:
    def is_valid_ip(self, ip_address: str) -> bool:
        """
        Checks if give string is a valid IPv4 address or IPv6 address.
        :param ip_address: String
        :return: True if valid otherwise False
        """
        if re.compile(IPv4_REGEX).match(ip_address):
            return True

        if re.compile(IPv6_REGEX).match(ip_address):
            return True

        return False

    @staticmethod
    def generate_random_ip(self) -> Optional[str]:
        """
        Generates random IP addresses and returns in string format.
        :return: IP address: String format.
        """
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        if self.is_valid_ip(ip):
            return ip

    def ip_to_int(self, ip_address: str) -> Optional[int]:
        """
        Converts IP address string to integer representation. For example, '192.168.100.1' --> 3232261121
        :param ip_address: IP address in string form
        :return: Integer representation of IP address string.
        """
        if self.is_valid_ip(ip_address) is True:
            return int(IPAddress(ip_address))

        logging.warning('Unable to convert ip: {} to integer representation')

    def int_to_ip(self, ip_integer) -> Optional[str]:
        """
        Converts integer form of IP address to string form i.e.
        3232261121--> '192.168.100.1'
        :param ip_integer: Integer representation of IP address.
        :return: String representation of IP address.
        """
        ip = str(IPAddress(ip_integer))
        if self.is_valid_ip(ip) is True:
            return ip

    def get_ip_for_url(self, url: str = None) -> Optional[str]:
        """
        This function returns the ip address of any given url.
        :param url: String
        :return:
        """
        try:
            if url is not None:
                parsed_url = urlparse(url)
                host = parsed_url.netloc.split(':')[0] or \
                    parsed_url.path.split('/')[0]
                ip = socket.gethostbyname(host.split(':')[0].split('/')[0])
                if self.is_valid_ip(ip) is True:
                    return ip

        except Exception as ex:
            logging.error('Unable to get ip address for url: {}. Error: {}'.format(url, ex))

        return None

    def generate_random_ip_with_mask(self) -> Optional[str]:
        """
        Generates random IP addresses and returns in string format.
        :return: IP address: String format.
        """
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        ip_address = '%s/%d' % (ip, random.randrange(8, 32))
        if self.is_valid_ip(ip_address) is True:
            return ip_address

    def inet_to_str(self, inet: bytes = '') -> Optional[str]:
        """
        Convert Inet address to a readable/printable string.
        :param inet: inet network address.
          :type: inet struct
        :return: Printable/readable MAC address
          :type: str
        """
        try:
            try:
                ip = socket.inet_ntop(socket.AF_INET, inet)         # IPv4 address

            except ValueError:
                ip = socket.inet_ntop(socket.AF_INET6, inet)      # IPv6 address

            if self.is_valid_ip(ip):
                return ip

        except Exception as ex:
            logging.error('Unable to convert Inet address to readable string. Error: {}'.format(ex))

        return None
