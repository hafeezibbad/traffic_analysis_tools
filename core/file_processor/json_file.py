import json
import logging
import os

from munch import Munch, DefaultMunch

from core.file_processor.base import FileProcessorBase
from core.file_processor.errors import FileError, FileErrorType


class JsonFileProcessor(FileProcessorBase):
    __valid_file_extensions = ['json']

    def read(self, file_path: str) -> Munch:
        if not file_path or os.path.exists(file_path) is False:
            raise FileError(
                message='File not found at path: {0}'.format(file_path),
                error_type=FileErrorType.INVALID_FILE_PATH
            )

        try:
            with open(file_path, 'r') as json_file:
                return DefaultMunch(None, json.load(json_file))

        except Exception as ex:
            raise FileError(
                message='Unable to load specified json file from path: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorType.FILE_PROCESSING_ERROR
            )

    def write(self, content: dict, file_path: str) -> bool:
        try:
            with open(file_path, 'w') as output:
                json.dump(content, output, indent=2, sort_keys=True)

                return True

        except Exception as e:
            logging.error('Unable to write json file to specified path: {}. Error: {}'.format(file_path, e))

        return False
