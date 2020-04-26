from pydantic import Extra

from core.models.common import Model


class ConfigurationData(Model):
    InputFileFolder: str = None
    ResultFileFolder: str = None
    ResultFileDelimiter: str = ','
    FieldDelimiter: str = ';'
    EtherTypeDataFilePath: str = None
    IpProtocolDataFilePath: str = None
    ManufFilePath: str = None
    TcpFlagDataFilePath: str = None
    TcpPortsFilePath: str = None
    p0f_executable: str = None
    p0f_wd: str = None
    use_numeric_values: bool = False

    class Config:
        extra = Extra.allow     # allow extra fields (not specific in schema) in configuration object.
