import logging
import os
import zipfile
from itertools import count
from pathlib import Path
from typing import Optional, Tuple, Union, List, Iterable, Set

from core.file_processor.errors import FileError, FileErrorType


def search_file(directory: str = None, filename: str = None, recursive: bool = True) -> Optional[str]:
    """Search for the file in given directory to look for given file.

    Parameters
    ----------
    directory: str
        Directory for searching the required file
    filename: str
        Name of file (including extension) being searched. Filename is case-sensitive
    recursive: bool
        Set this flag to recursively look for given file in specified directory path

    Returns
    -------
    file_path: str
        Absolute path to file in given directory, if file is found, otherwise `None`

    """
    print('1' * 80)
    if check_valid_path(directory, is_directory=True) is False or not filename:
        return None

    files = list_files_in_directory(directory=directory, recursive=recursive)
    print('searching files in {}: {}'.format(directory, files))
    for f in files:
        if os.path.basename(f) == filename:      # Linux filesystem is case sensitive
            return os.path.abspath(f)

    return None               # No file with given name found in the directory


def get_unique_filename(directory: str = None, filename: str = '', max_tries: int = 1000) -> Optional[str]:
    """Get unique filename in a directory by incrementing file name for storing the file, for example, 'filename001.ext'

    Parameters
    ----------
    directory: str
        Path to directory where filename should be unique
    filename: str
        Original file name
    max_tries: int
        Upper limit of number of attempts to find the unique filename

    Returns
    -------
    filename: str
        Unique filename in the given directory path.
        None is returned if directory or filename is invalid, or None
    """
    if check_valid_path(directory, is_directory=True) is False:
        logging.error('Invalid or non-existing directory: `%s` provided for file creation', directory)
        return None

    if not filename:
        logging.error('Invalid filename: `%s` provided for file creation', filename)
        return None

    _fname = ''.join(filename.split('.')[:-1]) + '-%03i.' + filename.split('.')[-1]
    _fname_gen = (os.path.join(directory, _fname) % i for i in count(1))
    unique_name = next(_fname_gen)

    for _ in range(max_tries):
        if not os.path.exists(os.path.abspath(unique_name)):
            break
        unique_name = next(_fname_gen)

    return unique_name


def has_valid_extension(file_path: str = None, valid_extensions: Union[list, set, Tuple] = None) -> bool:
    """ Check if given file has valid extension.

    Parameters
    -----------
    file_path: str
        name of file whose extension needs to be checked.
    valid_extensions: List[str], Set[str], Tuple[str]
        List, set, tuple of valid extensions, for example, ['csv', 'pcap']

    Returns
    -------
    success: bool
        True if no valid_extensions are specified or file has valid extension,otherwise False
    """
    if not valid_extensions:
        return True

    if file_path is None or not isinstance(valid_extensions, (list, set, tuple)):
        return False

    filename = os.path.basename(file_path)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in valid_extensions


def remove_files_from_directory(
        directory: str = None,
        file_extensions: Iterable[str] = None,
        recursive: bool = False
) -> List[str]:
    """Removes all files with given extension from the specified folder (optional: recursively)

    Parameters
    ----------
    directory: str
        Path to directory from where files should be removed
    file_extensions: Iterable[str]
        List, Set, tuple of file extensions which should be removed, for example, ["csv", "pcap"] (default=all files)
        Comma separated string, for example, "csv,pcap"
    recursive: bool
        Flag to specify whether to remove  files recursively from subfolders. (default=False)

    Returns
    -------
    file_paths: List[str]
        List of paths to files which were deleted

    Raises
    ------
    FileError: Exception
    """
    if check_valid_path(directory, is_directory=True) is False:
        raise FileError(
            message='Directory path specified for storing file: `{}` does not exist'.format(directory),
            error_type=FileErrorType.PATH_DOES_NOT_EXIST
        )

    deleted_files = []

    if isinstance(file_extensions, str):
        file_extensions = file_extensions.split(',')

    for f in os.listdir(directory):
        _fp = os.path.join(directory, f)

        if os.path.isdir(_fp) and recursive:
            deleted_files.extend(remove_files_from_directory(_fp, file_extensions, recursive))

        elif os.path.isfile(_fp):
            if file_extensions is None or os.path.basename(_fp).split('.')[-1] not in file_extensions:
                continue

            os.remove(_fp)
            deleted_files.append(_fp)

    return deleted_files


def search_file_in_directory(directory: str = None, filename: str = None, recursive: bool = True) -> Optional[str]:
    """Search for a given file in specified directory.

    Parameters
    ----------
    directory: str
        Path to directory for searching the files
    filename: str
        Name of file being searched
    recursive: bool
        Flag to specify if directory should be search recursively? Default= True

    Returns
    --------
    file_path: str
        Absolute path to file if found
        None if file is not found, or directory/filename is not specified

    Raises
    ------
    FileError: Exception
        If the path to directory does not exist, or specified path is not a directory
    """
    if not directory or not filename:
        return None
    if check_valid_path(directory, is_directory=True) is False:
        raise FileError(
            message='No directory found at specified path: `{}`'.format(directory),
            error_type=FileErrorType.INVALID_PATH
        )

    files = list_files_in_directory(directory, recursive=recursive)

    for f in files:
        if os.path.basename(f) == filename:  # Linux filesystem is case sensitive
            return os.path.abspath(f)

    return None  # No file with given name found in the directory


def list_files_in_directory(
        directory: str = None,
        extensions: List[str] = None,
        recursive: bool = True
) -> Optional[list]:
    """Recursive version for listdir which also gets files from subdirectories.

    Parameters
    ----------
    directory: str
        Path to directory for searching the files
    extensions:  List[st]
        (if specified) Only lists the files with given extensions.
    recursive: bool
        Flag to specify if directory should be search recursively? Default= True

    Raises
    ------
    FileError: Exception
        If the path to directory does not exist, or specified path is not a directory
    """
    if check_valid_path(directory, is_directory=True) is False:
        raise FileError(
            message='No directory found at specified path: `{}`'.format(directory),
            error_type=FileErrorType.INVALID_PATH
        )

    files = []
    for f in os.listdir(directory):
        if recursive is True and os.path.isdir(os.path.join(directory, f)):
            files.extend(list_files_in_directory(os.path.join(directory, f), extensions, recursive))

        # If extensions are specified, only add files which have given extension
        elif extensions and f.split('.')[-1] in extensions:
            files.append(os.path.abspath(os.path.join(directory, f)))

        # No extensions specified, add all files
        elif not extensions:
            files.append(os.path.abspath(os.path.join(directory, f)))

    return files


def get_filename_and_ext(file_path: str = None) -> Tuple[Optional[str], Optional[str]]:
    """Returns the file name and extension for the specified file.

    Parameters
    -----------
    file_path: str
        Path of the whose name is required.

    Returns
    --------
    file_name: str
        name of the specified file.
    extension: str
        file extension of the specified file.
    """
    if not file_path:
        return None, None

    f_name = os.path.basename(file_path)
    ext = f_name.split('.')[-1]

    return f_name, ext if ext.lower() != f_name.lower() else None


def extract_all_zips(
        directory: str = None,
        recursive: bool = True,
        delete_original: str = False,
        strict: bool = False
) -> List[str]:
    """Looks for any zip files in a folder and extract those zipped files.

    Parameters
    ----------
    directory: str
        Path where to look for zip files.
    recursive: bool
        Set this flag to recursively look for zip files in the directory. Default = True
    delete_original: bool
        Set this flag to delete original zip files after successful extraction. Default = False
    strict: bool
        Set this flag to raise exception if there is an exception in extracting one of the zip files. Default = False

    Returns
    --------
    count: int
        number of zipped files successfully extracted

    Raises
    ------
    FileError: Exception
        If specified directory path does not exist or is not a directory.
    """
    if check_valid_path(directory, is_directory=True) is False:
        return []

    extracted = []
    while True:
        zipped_files = list_files_in_directory(directory, extensions=['zip'], recursive=recursive)
        if len(zipped_files) == 0:
            break

        for zf in zipped_files:
            try:
                if zf not in extracted:
                    zip_ref = zipfile.ZipFile(zf, 'r')
                    zip_ref.extractall(zf)
                    zip_ref.close()
                    extracted.append(zf)
                    if delete_original:
                        os.remove(zf)   # Delete the original zipped file

            except Exception as ex:
                if strict is True:
                    raise ex
                logging.error('Unable to extract file: `%s`. Error: `%s`', zf, ex)

    return extracted


def check_valid_path(
        path: str = None,
        is_directory: bool = False,
        valid_extensions: Union[List[str], Tuple[str], Set[str]] = None
) -> bool:
    """Check that given path is valid, that is, it exists.

    Parameters
    ----------
    path: str
        Path which needs to be checked
    is_directory: bool
        Check if given path is a directory or not. Default: False
    valid_extensions: List[str], Set[str], Tuple[str]
        List, set, tuple of valid extensions, for example, ['csv', 'pcap']

    Returns
    -------
    valid: bool
        True if path is valid based on specified criteria, false otherwise
    """
    if not path:
        return False

    path = Path(path)
    if path.exists() is False:
        return False

    if is_directory and path.is_dir() is False:
        return False

    if has_valid_extension(path, valid_extensions=valid_extensions) is False:
        return False

    return True


def remove_file(file_path: str = None) -> bool:
    # FIXME: Add support for deleting multiple files and recursively using regex
    error_message = 'Unable to remove file at path `{file_path}`. Reason: `{reason}`'

    try:
        os.remove(file_path)

        return True

    except TypeError:
        logging.error(error_message.format(file_path=file_path, reason='Invalid file path'))

    except FileNotFoundError:
        logging.error(error_message.format(file_path=file_path, reason='File does not exist at specified path'))

    except PermissionError:
        logging.error(error_message.format(file_path=file_path, reason='Not enough permissions to modify/delete file'))

    return False
