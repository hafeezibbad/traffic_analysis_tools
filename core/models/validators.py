import re

from core.lib.ip_utils import IpAddrUtils
from core.lib.mac_utils import MacAddressUtils
from core.static.CONSTANTS import EMAIL_REGEX


class StrictNonEmptyStr(str):
    """Custom validator to ensure that the string value is not empty. for example, ''"""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value):
        if not isinstance(value, str):
            raise ValueError('Strict string: str expected, {} provided'.format(type(value)))

        if not value.strip():
            raise ValueError('Strict string: empty string provided')

        return value


class StrictMacAddressStr(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value):
        mac_utils = MacAddressUtils()
        if mac_utils.is_valid_mac(value) is False:
            raise ValueError('Invalid mac address format: expected format : or - separated, provided: {}'.format(value))

        return value


class StrictIPAddressStr(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value):
        ip_utils = IpAddrUtils()
        if ip_utils.is_valid_ip(value) is False:
            raise ValueError('Invalid IP address format: expected IPv4 or IPv6 address. provided: {}'.format(value))

        return value


def is_valid_email(email_address: str) -> bool:
    """
    Checks if give string is a valid email address or not.
    :param email_address: String
    :return: True if valid otherwise false
    """
    if not email_address:
        return False

    if re.compile(EMAIL_REGEX).match(email_address):
        return True

    return False
