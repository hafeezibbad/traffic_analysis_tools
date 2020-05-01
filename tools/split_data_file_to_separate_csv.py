from pathlib import Path  # noqa
import os
import sys

sys.path.append(os.getcwd())

# pylint: disable=wrong-import-position
from core.lib.mac_utils import MacAddressUtils  # noqa
from core.lib.common import print_json  # noqa
from core.pandas_utils.split_csv_data import extract_data_as_separate_csv  # noqa


if __name__ == '__main__':
    scripts_dir_path = Path(os.path.abspath(__file__)).parent
    project_dir_path = scripts_dir_path.parent
    input_file_path = project_dir_path / 'fixtures/results/results.csv'
    result_dir_path = project_dir_path / 'fixtures/results/splitted/'
    summary = extract_data_as_separate_csv(
        file_path=input_file_path,
        result_folder=result_dir_path,
        filter_columns=['src_mac', 'dst_mac'],
        sort_by_columns=['timestamp'],
        transform_function=MacAddressUtils().int_to_mac
    )
    print_json(summary)
