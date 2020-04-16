import os
import sys
import logging
from logging import Logger
from logging.handlers import RotatingFileHandler


def setup_logging(
        name: str,
        log_directory: str = os.getcwd(),
        file_name: str = 'log_file',
        max_file_size: int = 10000000,
        backup_count: int = 5
) -> Logger:
    """
    This function sets up logging for class
    :param name: name of the module calling logging setup function
    :param log_directory: directory to store logs
    :param file_name: filename for storing log information
    :param max_file_size: maximum size for logging file.
    :param backup_count: Number of backup log files
    :return logger: Logger object for the module
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    log_format = logging.Formatter('%(asctime)s - %(name)s %(levelname)s - %(message)s')

    # Create directory to store logs if it does not exist.
    if not os.path.exists(path=log_directory):
        os.makedirs(log_directory, exist_ok=True)

    log_fh = RotatingFileHandler(
        os.path.join(log_directory, file_name + '.log'),
        maxBytes=max_file_size,
        backupCount=backup_count
    )
    log_fh.setLevel(logging.INFO)
    log_fh.setFormatter(log_format)

    # Set up stream handler for important logs
    log_stream = logging.StreamHandler(stream=sys.stdout)
    log_stream.setFormatter(log_format)
    log_stream.setLevel(logging.DEBUG)

    # Add handlers
    logger.addHandler(log_fh)
    logger.addHandler(log_stream)

    return logger


def setup_simple_logging(name: str) -> Logger:
    """
    Setups up simple command line logging
    :param name: Name of module
    :return: Logger object
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    log_format = logging.Formatter('%(asctime)s - %(name)s %(levelname)s - %(message)s')

    # Set up stream handler for important logs
    log_stream = logging.StreamHandler(stream=sys.stdout)
    log_stream.setFormatter(log_format)
    log_stream.setLevel(logging.DEBUG)

    # Add handlers
    logger.addHandler(log_stream)

    return logger
