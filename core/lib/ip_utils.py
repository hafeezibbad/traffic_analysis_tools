import logging
import random
import re
import socket
import struct
from typing import Optional, Union
from urllib.parse import urlparse

from netaddr import IPAddress

from core.static.patterns import IP4_REGEX, IP6_REGEX


class IpAddrUtils:
    def is_valid_ip(self, ip_address: str) -> bool:
        """Checks if give string is a valid IPv4 address or IPv6 address.

        Parameters
        ----------
        ip_address: str
            IP address, for example 192.168.1.1
        Returns
        -------
        is_valid: bool
            True if IP address is valid otherwise False

        """
        if re.compile(IP4_REGEX).match(ip_address):
            return True

        if re.compile(IP6_REGEX).match(ip_address):
            return True

        return False

    def generate_random_ip(self) -> Optional[str]:
        """Generates random IP addresses and returns in string format.

        Returns
        -------
        IP address: str, optional
            Random IP address, for example, 192.168.1.1
        """
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        if self.is_valid_ip(ip):
            return ip

        return None

    def ip_to_int(self, ip_address: str) -> Optional[int]:
        """Converts IP address string to integer representation. For example, '192.168.100.1' --> 3232261121

        Parameters
        -----------
        ip_address: str
            IP address of format 192.168.1.1

        Returns
        -------
        ip_address: int
            Integer representation of IP address string.
        """
        if self.is_valid_ip(ip_address) is True:
            return int(IPAddress(ip_address))

        logging.warning('Unable to convert ip: `%s` to integer representation', ip_address)
        return None

    def int_to_ip(self, ip_integer: Union[int, str]) -> Optional[str]:
        """Converts integer form of IP address to string form, for example, int_to_ip(3232261121) -> '192.168.100.1'

        Parameters
        -----------
        ip_integer: int, str
            IP address of format 3232261121

        Returns
        -------
        ip_address: int
            Integer representation of IP address string, for example, '192.168.100.1'
        """
        try:
            ip_integer = int(ip_integer)
            ip = str(IPAddress(ip_integer))
            if self.is_valid_ip(ip) is True:
                return ip

        except Exception as ex:
            logging.error('Unable to convert IP (integer): `%s` to string. Error: `%s`', ip_integer, ex)

        return None

    def get_ip_for_url(self, url: str = None) -> Optional[str]:
        """This function returns the ip address of any given url.

        Parameters
        -----------
        url: str
            URL address

        Returns
        --------
        ip_address: str
            IP address hosting the given URL
            None if hostname can not be resolved
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
            logging.error('Unable to get ip address for url: `%s`. Error: `%s`', url, ex)

        return None

    def generate_random_ip_with_mask(self) -> Optional[str]:
        """Generates random IP addresses and returns in string format.

        Returns
        --------
        IP address: str
            IP address in string format, example, 192.168.1.1
        """
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        ip_address = '%s/%d' % (ip, random.randrange(8, 32))
        if self.is_valid_ip(ip_address) is True:
            return ip_address

        return None

    def inet_to_str(self, inet: bytes = '') -> Optional[str]:
        """Convert Inet address to a readable/printable string.

        Parameters
        -----------
        inet: bytes
            inet network address struct

        Returns
        -------
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
            logging.error('Unable to convert Inet address to readable string. Error: `%s`', ex)

        return None
