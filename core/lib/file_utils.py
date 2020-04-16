"""File related functions and features."""
import logging
import os
import zipfile
from itertools import count
from typing import Optional, Tuple, Union


def search_file(directory: str, filename: str) -> Optional[str]:
    """
    Search for the file in given directory to look for given file
    :param directory: Directory where we look for the file
    :param filename: Name of file we are looking for.
    :return file_path: full path if file exists, otherwise None
    """
    if not directory or not filename:
        return None

    files = recursive_listdir(directory=directory) or []
    for f in files:
        if os.path.basename(f) == filename:      # Linux filesystem is case sensitive
            return os.path.abspath(f)

    return None               # No file with given name found in the directory


def get_unique_filename(directory: str = None, filename: str = '') -> Optional[str]:
    """
    Increment file name for storing the file.
    :param directory: Folder for storing the filename
    :param filename: Original file name
    :return filename: Incremented filename e.g. 'filename001.ext'
    """
    if not directory or os.path.exists(directory) is False:
        logging.error('Invalid or non-existing directory: {} provided for file creation'.format(directory))
        return None

    if not filename:
        logging.error('Invalid filename: {} provided for file creation'.format(filename))
        return None

    _fname = ''.join(filename.split('.')[:-1]) + '-%03i.' + filename.split('.')[-1]
    _fname_gen = (os.path.join(directory, _fname) % i for i in count(1))
    unique_name = next(_fname_gen)

    while os.path.exists(os.path.abspath(unique_name)):
        unique_name = next(_fname_gen)

    return unique_name


def has_valid_extension(file_path: str, valid_extensions: Union[list, set, Tuple] = None) -> bool:
    """
    Check if given file has valid extension.
    :param filename: name of file whose extension needs to be checked.
    :param valid_extensions: set of valid extensions.
    :return result: boolean True if file has valid extension.
    """
    if not valid_extensions or not isinstance(valid_extensions, (list, set, tuple)):
        return False

    filename = os.path.basename(file_path)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in valid_extensions


def remove_files_from_directory(directory: str = None, extension: str = '', recursive: bool = False) -> Optional[int]:
    """
    Removes all files with given extension from the specified folder (optional: recursively)
    :param directory: folder path
    :param extension: (comma separated string) file extension e.g. "csv,pcap_files" (default=all files)
    :param recursive: remove files recursively from subfolders. (default=False)
    :return: Count of files deleted, None if there was an error
    """
    if not directory or not os.path.exists(directory):
        logging.error('path:{0} does not exist'.format(directory))
        return None

    count = 0

    if extension is not None:
        ext = extension.split(',')
    for f in os.listdir(directory):
        _fp = os.path.join(directory, f)

        if os.path.isdir(_fp) and recursive:
            count += remove_files_from_directory(_fp, extension, recursive)

        elif os.path.isfile(_fp):
            if ext and os.path.basename(_fp).split('.')[-1] in ext:
                os.remove(_fp)
                count += 1

            elif ext is None:
                os.remove(_fp)
                count += 1

    return count


def search_file_in_directory(directory: str, filename: str) -> Optional[str]:
    """
    Search for the file in given directory to look for given file
    :param directory: Directory where we look for the file
    :param filename: Name of file we are looking for.
    :return file_path: full path if file exists, otherwise None
    """
    if not directory or not filename:
        return None

    files = recursive_listdir(directory=directory) or []
    for f in files:
        if os.path.basename(f) == filename:  # Linux filesystem is case sensitive
            return os.path.abspath(f)

    return None  # No file with given name found in the directory


def recursive_listdir(directory: str = None, extension: str = None) -> Optional[list]:
    """
    Recursive version for listdir which also gets files from subdirectories
    :param directory: Root path to list all files
    :param extension: (if specified) Only lists the files with given extension.
    :return: list of all files in given directory and any subdirectories. None if folder path is invalid
    """
    if not directory or not os.path.exists(directory):
        logging.error('folder path: {0} is invalid'.format(directory))
        return None

    files = []
    for f in os.listdir(directory):
        if os.path.isdir(os.path.join(directory, f)):
            files.extend(recursive_listdir(directory=os.path.join(directory, f), extension=extension))

        elif extension is not None and f.split('.')[-1] == extension:
            files.append(os.path.abspath(os.path.join(directory, f)))

        elif extension is None:
            files.append(os.path.abspath(os.path.join(directory, f)))

    return files


def get_filename_and_ext(file_path: str) -> Optional[Tuple]:
    """
    Returns the file name and extension for the specified file.
    :param file_path: Path of the whose name is required.
        :type : <string>
    :return file_name: name of the specified file.
     :type : <string>
    :return extension: file extension of the specified file.
     :type : <string>
    """
    if not file_path:
        return None, None

    f_name = os.path.basename(file_path)
    ext = f_name.split('.')[-1]

    return f_name, ext if ext.lower() != f_name.lower() else None


def extract_all_zips(zip_file_path: str = None, remove_zips: str = False) -> int:
    """
    This routine looks for any .zip files in a folder including its subdirectories. It then extracts all the files
    from those zipped files.
    :param zip_file_path: Path where to look for zip files.
    :param remove_zips: If true, the original zip files are removed after extracting the compressed files.
    :return count: number of zipped files processed.
    """
    if zip_file_path is None or os.path.exists(zip_file_path) is False:
        return -1

    extracted = []
    count = 0
    while True:
        zipped_files = recursive_listdir(zip_file_path, extension='zip')
        if len(zipped_files) == 0:
            break

        for zf in zipped_files:
            try:
                if zf not in extracted:
                    zip_ref = zipfile.ZipFile(zf, 'r')
                    zip_ref.extractall(zf)
                    zip_ref.close()
                    extracted.append(zf)
                    if remove_zips:
                        os.remove(zf)   # Delete the original zipped file
                    count += 1

            except Exception as e:
                logging.error('Unable to extract file:{0}. Error:{1}'.format(zf, e))

    return count
