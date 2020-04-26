import unittest

from core.lib.ip_utils import IpAddrUtils
from core.lib.mac_utils import MacAddressUtils
from core.static.utils import StaticData
from tests.core.lib.common import CONFIGURATION_OBJ


class BasePacketParserTests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BasePacketParserTests, self).__init__(*args, **kwargs)
        self.ip_utils = IpAddrUtils()
        self.mac_utils = MacAddressUtils()
        self.config = CONFIGURATION_OBJ
        self.static_data = StaticData()

    def assertStrEqual(self, first: str, second: str, ignore_case: bool = False):
        if isinstance(first, str) is False:
            raise AssertionError('Invalid argument <>: expected <str>, provided <{}>'.format(first, type(first)))

        if isinstance(second, str) is False:
            raise AssertionError('Invalid argument <>: expected <str>, provided <{}>'.format(second, type(second)))

        if ignore_case is True:
            assert first.lower() == second.lower()

        assert first == second

