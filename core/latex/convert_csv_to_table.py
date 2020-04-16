# This module accepts a csv file as input and outputs a tex file containing data as a basic tex structure.
import argparse
from pathlib import Path


def convert_csv_to_tex(args):
    file_path = Path(args.input_file)
    if not file_path.exists():
        raise ValueError('Invalid/non-existing path `{}` provided for input CSV file')

    table_data = ""


    table_data = table_data + "\end{tabular}\n"
    table_data = table_data + "\end"




def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file', required=True, help='Input CSV file path')
    parser.add_argument('-o', '--output-file', default='table.tex', help='Output tex file path')
    parser.add_argument('-c', '--table-caption', default='Sample caption', help='Text for table caption')
    parser.add_argument('-l', '--table-label', default='sample_label',
                        help='Label used for Latex cross-reference. Format: `tbl:<table-label>')

    header_group = parser.add_argument_group('Headers options')
    header_group.add_argument('--headers', action='store_true', default=False, help='File contains headers')
    header_group.add_argument('--bold-headers', action='store_true', default=False,
                              help='Make headers bold in output tex table. This flag only works with --headers')
    header_group.add_argument('--header-rows', default=1, type=int, help='Number of rows used in header')

    style_group = parser.add_argument_group('Style options')
    style_group.add_argument('--center', action='store_true', default=False, help='Center the table content')

    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()

