import logging
from abc import ABC
import os
from typing import Optional, Generic, TextIO, List

from core.file_processor.errors import FileError, FileErrorType
from core.lib.file_utils import remove_files_from_directory, has_valid_extension
from core.errors.generic_errors import GenericError


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
    __valid_file_extensions = []

    def read(self, file_path: str) -> bool:
        raise NotImplementedError

    def write(self, content: Generic, output_file_path: str) -> bool:
        raise NotImplementedError

    @staticmethod
    def open_file(self, file_path: str = None, mode: str = 'r') -> TextIO:
        """Open file in given mode for read/write.

        Parameters
        ----------
        file_path: str
            Path to the file which needs to be opened
        mode: str
            File opening mode. Default: 'r'

        Returns
        -------
        file: TextIO
            File object for the opened files

        Raises
        ------
        FileError: Exception
            If the specified file path is None
            If no file exist at specified path
            if file can not be read/write from the specified path due to bad permissions

        """
        if not file_path:
            raise FileError(
                'No file path specified: {}'.format(file_path),
                error_type=FileErrorType.INVALID_FILE_PATH
            )

        try:
            return open(file_path, mode)

        except FileNotFoundError:
            raise FileError(
                message='File not found at specified path: `{}`'.format(file_path),
                error_type=FileErrorType.PATH_DOES_NOT_EXIST
            )

        except PermissionError:
            raise FileError(
                message='Not permitted to read/write file at specified path: `{}`'.format(file_path),
                error_type=FileErrorType.BAD_FILE_PERMISSIONS
            )

        except Exception as ex:
            raise FileError(
                message='Unable to access specified file: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorType.UNSPECIFIED_ERROR
            )

    def get_file_size(self, file_path: str = None) -> float:
        """Get the size (in kilobytes) for specified file

        Parameters
        ---------
        file_path: str
            path of file whose size is required.

        Returns
        -------
        file_size: float
            File size in kilobytes

        Raises
        ------
        FileError: Exception
            If the specified file path is None
            If no file exist at specified path
            if file can not be read/write from the specified path due to bad permissions
        """
        if not file_path:
            raise FileError(
                'No file path specified: {}'.format(file_path),
                error_type=FileErrorType.INVALID_FILE_PATH
            )

        try:
            return os.path.getsize(file_path) / 1000.0

        except FileNotFoundError:
            raise FileError(
                message='File not found at specified path: `{}`'.format(file_path),
                error_type=FileErrorType.PATH_DOES_NOT_EXIST
            )

        except PermissionError:
            raise FileError(
                message='Not permitted to read/write file at specified path: `{}`'.format(file_path),
                error_type=FileErrorType.BAD_FILE_PERMISSIONS
            )

        except Exception as ex:
            raise FileError(
                message='Unable to access specified file: {}. Error: {}'.format(file_path, ex),
                error_type=FileErrorType.UNSPECIFIED_ERROR
            )

    def create_empty_file(self, directory: str = None, file_size: int = 0) -> str:
        """Create an empty file of specified size at specified path.

        Parameters
        ----------
        directory: str
            path of file to be created.
        file_size: int
            size (in kilobytes) of the file to be created.

        Returns
        -------
        file_path: str
            Path to newly created file

        Raises
        -------
        GenericError: Exception
            Invalid file size specified for creating file
        FileError: Exception
            Can not create file due to OSError, PermissionError

        """
        try:
            if type(file_size) is str and str.isalnum(file_size):
                file_size = int(file_size)

        except ValueError:
            raise GenericError(
                'Invalid file size provided for file creation. Expected <int>, provided: {}'.format(type(file_size))
            )

        file_path = os.path.abspath(os.path.join(directory, str(file_size)))
        try:
            f = open(file_path, "wb")
            f.seek(file_size * 1000)
            f.write(b'\0')
            f.close()
            return file_path

        except OSError as e:
            raise FileError(
                message="Can not create a file of size: {} in folder: {}. Error: {}".format(file_size, directory, e),
                error_type=FileErrorType.UNSPECIFIED_ERROR
            )

        except Exception as e:
            raise FileError(
                message="Unable to create file at path: `{}`. Error: `{}`".format(file_path, e),
                error_type=FileErrorType.UNSPECIFIED_ERROR
            )

    def create_empty_files(
            self,
            directory: str = os.getcwd(),
            file_sizes: List[int] = None,
            strict: bool = False,
    ) -> Optional[List[str]]:
        """Create files of given sizes in given directory.

        Parameters
        ----------
        directory: str
            Path to folder where files should be stored
        file_sizes: List[int]
            List of (integer) file sizes to create.
        strict: bool
            Flag to specify whether function call should fail if any one of the files can not be created.

        Returns
        -------
        file_paths: List[str]
            List of paths to files which were successfully created.
            None is returned if given directory

        Raises
        ------
        FileError: Exception
            If directory path does not exist
            If file creation failed and strict flag is set
        """
        if not directory or os.path.exists(directory):
            raise FileError(
                message='Directory path specified for storing file: `{}` does not exist'.format(directory),
                error_type=FileErrorType.PATH_DOES_NOT_EXIST
            )

        files_created = []
        if not file_sizes:
            return files_created

        for fs in file_sizes:
            try:
                files_created.append(self.create_empty_file(directory=directory, file_size=fs))

            except Exception as ex:
                if strict is True:
                    raise ex
                logging.warning(
                    'Unable to create file of size: `{}` at path: `{}`. Error: `{}`'.format(fs, directory, ex)
                )

        return files_created

    def remove_files_from_folder(self, directory: str = None, recursive: bool = False) -> List[str]:
        return remove_files_from_directory(
            directory=directory,
            file_extensions=self.__valid_file_extensions,
            recursive=recursive
        )

    def has_valid_extension(self, file_path: str = None) -> bool:
        """Check if given file has specified extension.

        Parameters
        ----------
        file_path: str
            Path of file to check for having valid extension

        Returns
        -------
        status: bool
            True if file has valid extension, false otherwise
        """
        if not file_path:
            return False

        return has_valid_extension(file_path=file_path, valid_extensions=[self.__valid_file_extensions])
