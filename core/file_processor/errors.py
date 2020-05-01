class FileErrorType:
    # internal error code, HTTP status code, log event name
    FILE_NOT_FOUND = (0, 'FILE_NOT_FOUND')
    BAD_CONFIG_FILE = (1, 'BAD_CONFIGURATION_FILE')
    INVALID_CONFIG = (2, 'INVALID_CONFIGURATION_FILE')
    BAD_FILE_PERMISSIONS = (3, 'BAD_FILE_PERMISSIONS')
    FILE_PARSING_ERROR = (4, 'PARSING_ERROR')
    EMPTY_FILE = (6, 'EMPTY_FILE')
    INVALID_FILE_PATH = (7, 'INVALID_FILE_PATH')
    INVALID_FILE_TYPE = (8, 'INVALID_FILE_TYPE')
    UNSUPPORTED_FILE_TYPE = (9, 'UNSUPPORTED_FILE_TYPE')
    FILE_PROCESSING_ERROR = (10, 'FILE_PROCESSING_ERROR')
    UNSPECIFIED_ERROR = (11, 'UNSPECIFIED_ERROR')
    PATH_DOES_NOT_EXIST = (12, 'PATH_DOES_NOT_EXIST')
    INVALID_PATH = (13, 400, 'INVALID_PATH')


class FileError(Exception):
    message = None
    code = None
    event = None

    def __init__(self, message, error_type):
        self.message = message
        self.error_type = error_type
        self.code, self.event = error_type

    def __repr__(self):
        return self.message

    def __str__(self):
        return self.__repr__()
