import os
from typing import Dict, Any, Union

import yaml
from munch import Munch, DefaultMunch

from core.file_processor.base import FileProcessorBase
from core.file_processor.errors import FileError, FileErrorType


class YamlFileProcessor(FileProcessorBase):
    __valid_file_extensions = ['yml', 'yaml']

    def read(self, file_path: str) -> Munch:
        """Read a yaml file and return data as an object.

         Parameter
         ----------
         content: Dict[str, Any]
            Data to be written to YAML file.
         file_path: str
            Path to YAML file

         Parameter
         ----------
         content: Munch
            Data read from YAML file as python object

        Raises
        --------
        FileError: Exception
            If data can not be read to YAML file.
        """
        if not file_path or os.path.exists(file_path) is False:
            raise FileError(
                message='File not found at path: {0}'.format(file_path),
                error_type=FileErrorType.INVALID_FILE_PATH
            )

        try:
            with open(file_path, 'r') as yaml_file:
                return DefaultMunch(None, yaml.safe_load(yaml_file))

        except Exception as ex:
            raise FileError(
                message='Unable to load specified yaml file from path: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorType.FILE_PROCESSING_ERROR
            )

    def write(self, data: Union[Munch, Dict[str, Any]], file_path: str):
        """Write a yaml file and return data as an object.

         Parameter
         ----------
         data: Dict[str, Any]
            Data to be written to YAML file.
         file_path: str
            Path to YAML file for writing the data

        Raises
        --------
        FileError: Exception
            If data can not be written to YAML file.
        """
        try:
            with open(file_path, 'w') as output:
                yaml.dump(data, output, default_flow_style=False)

        except Exception as ex:
            raise FileError(
                message='Unable to write yaml file to specified path: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorType.FILE_PROCESSING_ERROR
            )
