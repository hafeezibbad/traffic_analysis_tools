import json
import logging
import os

import yaml
from munch import Munch, DefaultMunch

from core.file_processor.base import FileProcessorBase
from core.file_processor.errors import FileError, FileErrorTypes


class YamlFileProcessor(FileProcessorBase):
    __EXTENSION__ = 'yml,yaml'

    def read(self, file_path: str) -> Munch:
        """
        Read a yaml file and return data as an object
        :param file_path: Path to JSON file
        :return: Object containing JSON data
        :raises: FileError
        """
        if not file_path or os.path.exists(file_path) is False:
            raise FileError(
                message='File not found at path: {0}'.format(file_path),
                error_type=FileErrorTypes.INVALID_FILE_PATH
            )

        try:
            with open(file_path, 'r') as yaml_file:
                return DefaultMunch(None, yaml.safe_load(yaml_file))

        except Exception as ex:
            raise FileError(
                message='Unable to load specified yaml file from path: {}.Error: {}'.format(file_path, ex),
                error_type=FileErrorTypes.FILE_PROCESSING_ERROR
            )

    def write(self, content: dict, file_path: str):
        """
        Write a yaml file and return data as an object
        :param content: Data to be written to YAML file.
        :param file_path: Path to YAML file
        :raises: FileError
        """
        try:
            with open(file_path, 'w') as output:
                yaml.dump(content, output, default_flow_style=False)

        except Exception as ex:
            raise FileError(
                message='Unable to write yaml file to specified path: {}.Error: {}'.format(file_path, ex),
                error_type=FileErrorTypes.FILE_PROCESSING_ERROR
            )
