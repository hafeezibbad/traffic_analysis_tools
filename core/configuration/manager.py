from typing import Optional

from .data import ConfigurationData
from .errors import ConfigurationError, ConfigurationErrors
from .parser import ConfigurationParser


class ConfigurationManager:

    def __init__(self, configuration_type=ConfigurationData):
        self.configuration_parser = ConfigurationParser()
        self.configuration_type = configuration_type

    def __read_data_from_configuration_file(self, file_path: str = None) -> dict:
        """
        This function parses the data in configuration file and reads it to a dictionary object
        :param file_path: path to configuration file
        :return: data read from configuration file
        :raises:
            ConfigurationError: if the file is not available, can not be read, has bad file permissions, or can not
            be parsed.
        """
        try:
            config_data = self.configuration_parser.parse(file_path)

            return config_data

        except Exception as ex:
            raise ConfigurationError(
                message='Unable to parse configuration file',
                code=ConfigurationErrors.CONFIG_PARSING_ERROR
            ) from ex

    def __load_config_data_to_config_object(self, config_data: dict = None) -> Optional[ConfigurationData]:
        """
        This function reads configuration data, provided as a dictionary object, to a configuration object.
        :param config_data: data read from configuration file
        :return:
            A configuration data object of specific type.
        :raises:
            ConfigurationError.INVALID_CONFIG: The data read from configuration file can not be loaded to an object of
            specific type.
        """
        if not config_data:
            return None

        try:
            configuration_obj = self.configuration_type.load(data=config_data)

        except (ValueError, KeyError) as ex:
            raise ConfigurationError(
                message='Configuration file can not be validated',
                code=ConfigurationErrors.INVALID_CONFIG
            ) from ex

        return configuration_obj

    def load_data_from_configuration_file(self, file_path: str = None) -> Optional[ConfigurationData]:
        """
        Read yaml configuration file and load it as Configuration object after validating the configuration
        :param file_path: data read from configuration file
        :return:
            A configuration data object of specific type.
        :raises:
            ConfigurationError:
            1. If there is no or invalid path specific for configuration file
            2. No file is available at specified path
            3. File at specific path can not be read, possibly due to bad permissions
            4. Specified configuration file can not be parsed
                a. Due to parsing error
                b. Due to unsupported file type
            5. The data read from configuration file can not be loaded to object of specific type.
        """

        config_data = self.configuration_parser.parse(file_path)
        config_obj = self.__load_config_data_to_config_object(config_data)

        return config_obj
