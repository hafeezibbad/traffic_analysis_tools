import logging
from abc import ABC
import os
from typing import Optional, Generic, Tuple

from core.lib.file_utils import remove_files_from_directory, has_valid_extension


class FileProcessorABC(ABC):
    @staticmethod
    def read(file_path: str) -> bool:
        pass

    @staticmethod
    def write(content: Generic, output_file_path: str) -> bool:
        pass

    @staticmethod
    def get_file_size(file_path: str) -> int:
        pass

    @staticmethod
    def create_empty_file(directory: str = None, file_size: int = 0) -> bool:
        pass

    @staticmethod
    def create_empty_files(directory: str = None, file_size: int = 0) -> bool:
        pass

    @staticmethod
    def remove_files_from_folder(directory: str = None, recursive: bool = False) -> Optional[int]:
        pass

    @staticmethod
    def has_valid_extension(file_path: str = None) -> bool:
        pass


class FileProcessorBase(FileProcessorABC):
    __EXTENSION__ = ''

    def read(self, file_path: str) -> bool:
        raise NotImplementedError

    def write(self, content: Generic, output_file_path: str) -> bool:
        raise NotImplementedError

    def get_file_size(self, file_path: str) -> float:
        """
        Get the size (in kilobytes) for specified file
        :param file_path: path of file whose size is required.
            :type: <string>
        :return file_size: File size in kilobytes
        """
        try:
            return os.path.getsize(file_path) / 1000.0

        except FileNotFoundError:
            logging.error('Request file does not exist at {0}'.format(file_path))

        except Exception as e:
            logging.error('Unable to find file size for {0}. Error: {1}'.format(file_path, e))

        return -1

    def create_empty_file(self, directory: str = None, file_size: int = 0) -> bool:
        """
        Create a file of specified size at specified path
        :param directory: path of file to be created.
         :type:
        :param file_size: size (in kilobytes) of the file to be created.
         :type: <int>
        :return: True if file created successfully otherwise

        """
        try:
            if type(file_size) is str and str.isalnum(file_size):
                file_size = int(file_size)

        except ValueError:
            logging.error('Invalid file size provided for file creation. Expected <int>, provided: {}'.format(
                file_size))
            return False

        try:
            f = open(os.path.join(directory, str(file_size)), "wb")
            f.seek(file_size * 1000)
            f.write(b'\0')
            f.close()
            return True

        except OSError as e:
            logging.error("Can not create a file of size: {} in folder: {}.Error: {}".format(file_size, directory, e))

        return False

    def create_empty_files(self, directory: str = os.getcwd(), file_sizes: list = None) -> Optional[Tuple]:
        """
        Create files of given sizes
        :param directory: folder for creating the files.
        :param file_sizes: List of file sizes to create.
        :return list of failures when creating files of given sizes in specified folder path. None if folder size is
        unspecified or folder path is invalid or empty.
        """
        if not directory or os.path.exists(directory):
            logging.error('Unable to create any file at specified folder: {}'.format(directory))
            return None

        if not file_sizes:
            return None

        failure = []
        success = []
        for fs in file_sizes:
            res = self.create_empty_file(directory=directory, file_size=fs)
            if res is False:
                failure.append(fs)
            else:
                success.append(fs)

        return success, failure

    def remove_files_from_folder(self, directory: str = None, recursive: bool = False) -> Optional:
        return remove_files_from_directory(directory=directory, extension=self.__EXTENSION__, recursive=recursive)

    def has_valid_extension(self, file_path: str = None) -> bool:
        if not file_path:
            return False

        return has_valid_extension(file_path=file_path, valid_extensions=[self.__EXTENSION__])
