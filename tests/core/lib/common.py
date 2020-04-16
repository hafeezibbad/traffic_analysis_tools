from core.configuration.data import ConfigurationData
from core.static.CONSTANTS import ETHER_TYPES_DATA_FILE_PATH, IP_PROTOCOLS_DATA_FILE_PATH, MANUF_DATA_FILE_PATH, \
    TCP_FLAGS_DATA_FILE_PATH, LAYER4_PORTS_DATA_FILE_PATH

CONFIGURATION_DATA = dict(
    InputFileFolder='/mock/file/path',
    ResultFileFolder='/mock/reults/path',
    ResultFileDelimiter=',',
    FieldDelimiter=';',
    EtherTypeDataFilePath=ETHER_TYPES_DATA_FILE_PATH,
    IpProtocolDataFilePath=IP_PROTOCOLS_DATA_FILE_PATH,
    ManufFilePath=MANUF_DATA_FILE_PATH,
    TcpFlagDataFilePath=TCP_FLAGS_DATA_FILE_PATH,
    TcpPortsFilePath=LAYER4_PORTS_DATA_FILE_PATH
)

CONFIGURATION_OBJ = ConfigurationData.load(data=CONFIGURATION_DATA)
