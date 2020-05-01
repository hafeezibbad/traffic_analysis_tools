import logging
import time
import os

from pathlib import Path
from typing import Any, List, Union, Dict, Callable, Optional
from munch import DefaultMunch
import pandas as pd
from pandas import DataFrame

from core.errors.generic_errors import GenericError


def extract_data_as_separate_csv(
        file_path: Path = None,
        result_folder: Path = Path(os.getcwd()),
        filter_columns: List[str] = None,
        sort_by_columns: List[str] = None,
        transform_function: Callable[[Union[int, str]], str] = None
) -> Dict[str, Any]:
    """Read a CSV file from specified path, and extract the unique values from specified `filter_columns` in separate
    CSV files.

    Example:
    If we want to extract data for unique MAC addresses appeared in source, destination MAC address
    fields to individual files, we can call the function as split_csv(input_file, results_folder, data_columns=[
    'src_mac', 'dst_mac']). This will look for all unique MAC addresses appeared in 'src_mac' or 'dst_mac' columns.
    For each of these MAC addresses, it will filter all rows where that mac address appeared in 'src_mac' or
    'dst_mac' columns, and output the result to separate CSV file (in specified results_folder). At the end,
    the function will provide summary object where keys are unique MAC addresses, and values contain path to output
    file, and number of rows in the output file for specific MAC address.


    Parameters
    -----------
    file_path: str
        Path to input data file
        :type: string
    result_folder: str
        Path to folder where output CSV files should be written. default: current working directory
    filter_columns: List[str]
        columns from where unique values are extracted
    transform_function: function
        This function is used to transform unique values to human-understandable format. For example, data file
        contains MAC address as integer. If filtering is done over mac address, you can pass a transform function which\
         converts integer representation to MAC to be used in file-names, and summary data

    Returns
    -------
    summary: dictionary
        JSON (dictionary object) containing

    Raises
    ------
    GenericError: exception
        Error raised if
        - Input file does not exist, or specified path is directory
        - Output folder path does not exist or specified path is not a directory
        - Data can not be loaded to DataFrame from a CSV file
        - Data can not be written from DataFrame to a CSV file
    """
    output_folder = Path(result_folder)
    if output_folder.exists() is True and output_folder.is_dir() is False:
        raise GenericError('Specified output folder `{}` is not a directory'.format(result_folder))
    if output_folder.exists() is False:
        os.makedirs(output_folder, exist_ok=True)

    data = load_csv_to_dataframe(file_path, fill_empty_values=True, verify_columns_exist=filter_columns)
    base_filename_id = file_path.name.strip().split('.')[0]
    summary_data = DefaultMunch()

    unique_values = []
    for col in filter_columns:
        unique_values.extend(list(data[col].unique()))

    unique_values = set(unique_values)
    logging.debug('`%s` unique values', len(unique_values))

    for val in unique_values:
        st = time.time()
        if transform_function is not None:
            str_val = transform_function(val)
        else:
            str_val = val

        output_file_path = '{folder}/{prefix}-{value}.csv'.format(
            folder=output_folder,
            prefix=base_filename_id,
            value=str_val
        )
        filtered_data = get_filtered_data_from_data_frame(data, filter_columns, val, sort_by_columns)
        write_dataframe_to_csv_file(filtered_data, output_file_path, True, header=True, index=False)

        summary_data[str_val] = DefaultMunch(
            file=output_file_path,
            row_count=filtered_data.shape[0],
            time_taken=time.time() - st
        )
        logging.debug(
            'Successfully filtered data for value = `%s` to `%s` in `%s` seconds',
            str_val,
            summary_data[str_val]['file'],
            summary_data[str_val]['time_taken']
        )

    return summary_data


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


def load_csv_to_dataframe(
        file_path: str = None,
        fill_empty_values: bool = True,
        fillna_value: Union[str, int] = 0,
        verify_columns_exist: List[str] = None
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
    verify_columns_exist: List[str]
        Verify that these columns exist in the CSV file

    Returns
    -------
    data: Dataframe
        Data frame object containing data read from CSV file

    Raises
    ------
    GenericError
        If no file exists at specified path, or specified path is a directory
        If data from CSV file can not be loaded in to DataFrame
        If one or more columns specified in `verify_cloumns_exist` do not exist in data file
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

    data_columns = data.columns
    for col in verify_columns_exist:
        if col not in data_columns:
            raise GenericError('Specified column name: `{}` not found in input csv file. Columns available in data '
                               'file: `{}`'.format(col, data_columns))

    return data


def get_filtered_data_from_data_frame(
        data: DataFrame,
        filter_columns: List[str],
        value: Union[str, int],
        sort_by_columns: List[str]
) -> DataFrame:
    """Filter all rows containing given value in one of the filter_columns.

    Example: If the goals is to get all data rows where given MAC address is src or destination MAC address,
    this can be achieved by calling get_filtered_data_from_data_frame(data, filter_columns=['src_mac', 'dst_mac'],
    '00:11:22:33:44:55') which returns all rows where given MAC address '00:11:22:33:44:55' appears in either
    'src_mac' or 'dst_mac' columns. The results can be sorted by column names specified in sort_by_columns.

    Parameters
    -----------
    data: DataFrame
        Data frame containing data loaded from csv file
    value: str, int
        Value which should be used for filtering rows
    filter_columns: List[str], Set[str]
        List of columns where given value should be present in one of these columns
    sort_by_columns: List[str], Set[str]
        List of columns which should be used for sorting the results.

    Returns
    -------
    data: Dataframe
        Data frame object containing rows (from input data frame) which contains given (input) value in one of the
        columns specified in `filter_columns`

    Raises
    ------
    GenericError
        Error if filter_columns are not available in data frame.
    """
    logging.debug('`%s` Rows read from CSV file', data.shape[0])
    if not isinstance(filter_columns, list):
        raise GenericError(
            'Invalid data provided as filter_columns. expected: <List>, provided: `{}`'.format(type(filter_columns))
        )

    columns_to_be_processed = filter_columns or [] + sort_by_columns or []
    data_columns = data.columns
    for col in columns_to_be_processed:
        if col not in data_columns:
            raise GenericError('Specified column name: `{}` not found in input data frame. Columns available in data '
                               'file: `{}`'.format(col, data_columns))

    if value is None:
        return data

    intermediate_filtered_data = [data[data[col] == value] for col in data_columns]
    filtered_data = pd.concat(intermediate_filtered_data, ignore_index=True)
    if sort_by_columns:
        filtered_data.sort_values(by=sort_by_columns, inplace=True)

    return filtered_data
