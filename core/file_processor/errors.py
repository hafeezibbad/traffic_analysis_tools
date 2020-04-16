import logging


class FileErrorTypes:
    # internal error code, HTTP status code, log event name
    FILE_NOT_FOUND = (0, 500, 'CONFIG_FILE_NOT_FOUND')
    BAD_CONFIG_FILE = (1, 500, 'BAD_CONFIGURATION_FILE')
    INVALID_CONFIG = (2, 500, 'INVALID_CONFIGURATION_FILE')
    BAD_FILE_PERMISSIONS = (3, 500, 'BAD_FILE_PERMISSIONS')
    CONFIG_PARSING_ERROR = (4, 500, 'CONFIG_PARSING_ERROR')
    EMPTY_CONFIG_FILE = (6, 500, 'EMPTY_CONFIG_FILE')
    INVALID_FILE_PATH = (7, 404, 'INVALID_FILE_PATH')
    INVALID_FILE_TYPE = (8, 400, 'INVALID_FILE_TYPE')
    UNSUPPORTED_FILE_TYPE = (9, 500, 'UNSUPPORTED_FILE_TYPE')
    FILE_PROCESSING_ERROR = (10, 500, 'FILE_PROCESSING_ERROR')


class FileError(Exception):
    http_status = None
    code = None
    event_name = None
    message = None

    def __init__(self, message, error_type):
        self.message = message
        self.error_type = error_type
        self.code, self.http_status, self.event_name = error_type

    def __repr__(self):
        return self.message

    def __str__(self):
        return self.__repr__()
