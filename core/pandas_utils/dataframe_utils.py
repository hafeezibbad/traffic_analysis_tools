from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pandas import DataFrame
import pandas as pd

from core.errors.generic_errors import GenericError


def load_csv_to_dataframe(
        file_path: Union[Path, str] = None,
        fill_empty_values: bool = True,
        fillna_value: Union[str, int] = 0,
        verify_columns: List[str] = None,
        strict: bool = False
) -> DataFrame:
    """Read CSV file and load data to DataFrame

    Parameters
    -----------
    file_path: str
        Path to CSV file containing data
    fill_empty_values: bool
        Boolean flag to specify if empty values should be filled in DataFrame
    fillna_value: Union[str, int]
        Default value for filling empty cells in DataFrame
    verify_columns: List[str]
        Verify that these columns exist in the CSV file
    strict: bool
        Set this flag to raise Generic error if any columns are missing from the data frame.

    Returns
    -------
    data: Dataframe
        Data frame object containing data read from CSV file

    Raises
    ------
    GenericError
        If no file exists at specified path, or specified path is a directory
        If data from CSV file can not be loaded in to DataFrame
        If one or more columns specified in `verify_cloumns` do not exist in data file, and strict flag is set
    """
    file_path = Path(file_path)
    if file_path.exists() is False or file_path.is_dir() is True:
        raise GenericError('File does not exist at specified path: `{}`'.format(file_path))

    try:
        data = pd.read_csv(file_path)
        if fill_empty_values is True:
            data.fillna(fillna_value, inplace=True)

    except Exception as ex:
        raise GenericError('Can not read file specified at `{}`. Error: {}'.format(file_path, ex))

    missing_columns = verify_columns_exist_in_dataframe(data, verify_columns)
    if strict is True and not missing_columns:
        raise GenericError('`{}` not found in input csv file'.format(','.join(missing_columns)))

    return data


def verify_columns_exist_in_dataframe(data: DataFrame, verify_columns: List[str]) -> List[str]:
    """Verify that specific set of columns exist in given data frame.
    Parameters
    ----------
    data: DataFrame
        Data frame object containing data loaded from CSV file.
    verify_columns: List[str]
        List of columns which should exist in data frame

    Returns
    -------
    missing_columns: List[str]
        List of column names which are not available in data frame.
    """
    missing_columns = []
    if not verify_columns:
        return missing_columns

    data_columns = data.columns
    for col in verify_columns:
        if col not in data_columns:
            missing_columns.append(col)

    return missing_columns


def write_dataframe_to_csv_file(
        data: DataFrame,
        file_path: str,
        overwrite: bool = True,
        **kwargs: Dict[str, Any]
) -> Optional[str]:
    """Write given DataFrame to CSV file at specified path.

    Parameters
    ----------
    data: DataFrame
        Data to be written to csv file
    file_path: str
        Path where output CSV file should be written
    overwrite: bool
        If the file already exists, overwrite the file with new data. `True` by default
    **kwargs: dict
        Keyword arguments, passed directly to `DataFrame.to_csv()` function

    Returns
    -------
    file_path: str
        Path where CSV file was written. `None`  returned if  input data is `None`

    Raises
    ------
    GenericError: Exception
        Error raised if
        - file already exists at specified path and overwrite is False.
        - Specified file path is a directory
        - data can not be written to specified path
    """
    if data is None:
        return None
    if Path(file_path).exists() and overwrite is False:
        raise GenericError('A file already exists at specified path: `{}`, and overwrite is disabled'.format(file_path))
    if Path(file_path).is_dir() is True:
        raise GenericError('Specified file_path: `{}` is a directory'.format(file_path))

    try:
        data.to_csv(file_path, **kwargs)
    except Exception as ex:
        raise GenericError(
            'Could not write dataframe to csv file at specified path: `{}`. Error: `{}`'.format(file_path, ex)
        )

    return None
