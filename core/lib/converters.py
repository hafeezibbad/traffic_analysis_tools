import datetime
from core.static.patterns import DATE_TIME_FORMAT


def get_date_identifier(timestamp: float) -> str:
    """
    Extract the identifier from starting date of trace.

    Parameter
    ---------
    timestamp: integer
        starting time for the trace.

     Return
     ------
    identifier: string
        id for the trace file results.
    """
    date_str = datetime.datetime.fromtimestamp(timestamp).strftime(DATE_TIME_FORMAT)

    return ''.join(date_str.split('-')[:-1])    # Don't include seconds


def timestamp_to_formatted_date(seconds: float, str_format: str = "%Y-%m-%d %H:%M:%S"):
    """
    Convert the seconds from epoch to human readable date.

    Parameter
    ---------
    seconds: integer
     seconds from epoch
    str_format: str
        Format of human readable date string.
    Return
    --------
    datetime: string
        Date string in human readable format
    """
    return datetime.datetime.utcfromtimestamp(seconds).strftime(str_format)


def hex_to_integer(hex_value: str) -> int:
    """Converts hex value to integer value.

    Example: hex_to_integer('888e') => 34958
    Parameter
    ---------
    hex_value: string
        String representation of hex value, for example '888e'
    Return
    ------
    value: integer
        Integer representation of given hex value
    """
    if not hex_value:
        return -1

    return int(hex_value, 16)


def bool_to_integer(boolean_flag: bool) -> int:
    """Convert a boolean flag to integer (0 or 1) if the value is not boolean, returns 0"""
    if boolean_flag is True:
        return 1

    return 0
