from munch import Munch, DefaultMunch
from numpy import ndarray
from pandas import DataFrame
import numpy as np
import pandas as pd

from core.extended_features import DATA_VECTOR
from core.extended_features.stats import calculate_quantiles, calculate_entropy, make_bins


def get_summary_statistics_for_time_based_features():
    pass


def calculate_inter_arrival_time(data: DataFrame) -> DataFrame:
    """Calculate the time difference between incoming packets.

    This function takes complete data frame containing data extracted from pcap file. It uses `ref_time` field to
    calculate the inter-arrival time between packets.

    Parameters
    ----------
    data: DataFrame
        Data frame object containing data extracted from pcap files

    Returns
    -------
    iat_data: DataFrame:
        Data frame containing two columns, `ref_time` and `iat` (inter-arrival-time) calculated from ref_time field in
        input data.
    """
    data = DataFrame(data={'ref_time': data['ref_time'], 'ref_time_off_by_1': data['ref_time']})
    data['ref_time_off_by_1'] = data['ref_time_off_by_1'].shift(1, fill_value=0)
    data['iat'] = data['ref_time'] - data['ref_time_off_by_1']
    data.drop(columns=['ref_time_off_by_1'], inplace=True)

    return data
