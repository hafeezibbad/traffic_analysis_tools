from click import Tuple
from munch import Munch, DefaultMunch
from pandas import DataFrame


def extract_data_for_specific_value(df: DataFrame, column: str, value: str) -> DataFrame:
    if column not in df:
        return DataFrame(columns=df.columns.to_list)

    return df[df[column] == value]
