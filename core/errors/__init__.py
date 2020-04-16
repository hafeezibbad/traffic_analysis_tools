class FileErrorTypes:
    FILE_NOT_FOUND = (0, 404, 'FILE_NOT_FOUND')
    BAD_PERMISSIONS = (1, 403, 'BAD_PERMISSIONS')
    FILE_NOT_EXIST = (2, 400, 'FILE_DOES_NOT_EXIST')
    UNSPECIFIED_ERROR = (3, 500, 'UNSPECIFIED_ERROR')
    INVALID_FILE_PATH = (4, 400, 'INVALID_FILE_PATH')


class FileError(Exception):
    message = None
    code = None
    http_status = None
    event = None

    def __init__(self, message, error_type):
        self.message = message
        self.error_type = error_type
        self.code, self.http_status, self.event = error_type

    def __repr__(self):
        return self.message

    def __str__(self):
        return self.__repr__()
