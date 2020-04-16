import json
import os

import yaml

from core.file_processor.errors import FileError
from core.file_processor.json_file import JsonFileProcessor
from core.file_processor.yaml_file import YamlFileProcessor
from core.lib.file_utils import get_filename_and_ext
from .errors import ConfigurationError, ConfigurationErrors


class ConfigurationParser:

    SUPPORTED_TYPES = ['json', 'yml', 'yaml']

    def __init__(self):
        self.config_data = dict()

    def parse(self, file_path: str = None) -> dict:
        """
        Parse the configuration file.
        :param file_path: Path to configuration file which needs to be parsed.
        :return: json object containing configuration data.
        :raises:
            ConfigurationError.INVALID_FILE_TYPE: In case there is no file type available form config file, e.g., .json
            ConfigurationErrors.UNSUPPORTED_FILE_TYPE: In case no parser is available for given file type
        """
        if not file_path:
            raise ConfigurationError(
                message='No configuration file path specified',
                code=ConfigurationErrors.INVALID_FILE_PATH
            )

        if os.path.exists(file_path) is False:
            raise ConfigurationError(
                message='Configuration file not found',
                code=ConfigurationErrors.FILE_NOT_FOUND
            )

        file_type = self.__extract_file_type(file_path)
        if '.' not in file_path and file_type == file_path:
            raise ConfigurationError(
                message='No file type given for configuration file',
                code=ConfigurationErrors.INVALID_FILE_TYPE
            )

        try:
            parser_func = getattr(self, 'parse_{}'.format(file_type))
            self.config_data = parser_func(file_path=file_path)

            return self.config_data

        except ConfigurationError as ex:
            raise ex

        except AttributeError:
            raise ConfigurationError(
                message='Unsupported file type `{}` of configuration file'.format(file_type),
                code=ConfigurationErrors.UNSUPPORTED_FILE_TYPE
            )

        except Exception as ex:
            raise ConfigurationError(
                message='Unable to parse configuration file',
                code=ConfigurationErrors.CONFIG_PARSING_ERROR
            ) from ex

    def parse_yml(self, file_path: str = None) -> dict:
        """
        This function reads a configuration file in yml format and returns it in json format.
        :param file_path: path of yaml configuration file.
        :return: json object containing configuration.
        :raises:
            ConfigurationError.FILE_NOT_FOUND: Configuration not found at specified path
            ConfigurationError.BAD_CONFIG_FILE: Invalid file
        """
        return self.parse_yaml(file_path)

    def parse_yaml(self, file_path: str = None) -> dict:
        """
        This function reads a configuration file in yaml format and returns it in json format.
        :param file_path: path of yaml configuration file.
        :return: json object containing configuration.
        :raises:
            ConfigurationError.FILE_NOT_FOUND: Configuration not found at specified path
            ConfigurationError.BAD_CONFIG_FILE: Invalid file
        """
        yaml_processor = YamlFileProcessor()
        try:
            return yaml_processor.read(file_path).toDict()

        except FileError as ex:
            raise ConfigurationError(message=ex.message, code=ex.error_type)

    def parse_json(self, file_path: str) -> dict:
        """
        This function reads a configuration file in json format and returns as dictionary object.
        :param file_path: path of json configuration file.
        :return: json object containing configuration.
        :raises:
            FileNotFoundError: Configuration not found at specified path
            TypeError: Invalid file
        """
        json_processor = JsonFileProcessor()
        try:
            return json_processor.read(file_path).toDict()

        except FileError as ex:
            raise ConfigurationError(message=ex.message, code=ex.error_type)

    def __extract_file_type(self, file_path: str) -> str:
        """Extract file type from file extension."""
        return get_filename_and_ext(file_path)[1]
