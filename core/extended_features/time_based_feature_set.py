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


def calculate_stats_over_n_items(data: DATA_VECTOR, n_items: int = None) -> DataFrame:
    """ Calculate summary statistics over n items in the data object.

    This function receives a list of values and calculates a set of statistics including sum, min, max, mean,
    25/50/75/90 percentile, IQR, standard deviation, and entropy.
    Example input: calculate_stats_over_n_items(data = [1, 3, 5, 2, 3, 5, 3, 2, 1, 3, 4, 5], n = 3). The function will
    divide the input into list of 3 values each. For each set, it will calculate all statistics. The return will be
    [values | max | min | sum | mean | stdev | q25 | q50 | q75 | q90 | iqr | entropy]

    Parameters
    ----------
    data: DATA_VECTOR
        ndarray/List of integer or float values to calculate the sum.
    n_items: int
        Size of subset for calculating stats
        If n_items is None or n_items < len(data), stats are calculated over all the data provided.

    Returns
    -------
    stats_df: DataFrame
        Data frame containing summary statistics calculated from given data
    """
    if not n_items or len(data) <= n_items:
        return compile_data_frame_including_stats(data)

    data_bins = make_bins(data, n_items)
    stats_df = None
    for each in data_bins:
        stats = compile_data_frame_including_stats(each, column_prefix=n_items)
        if stats_df is None:
            stats_df = stats
        else:
            stats_df = pd.concat([stats_df, stats], axis=0)  # Row wise stacking

    return stats_df


def compile_data_frame_including_stats(data: DataFrame, column_prefix: str = None) -> DataFrame:
    """This function adds summary statistics as additional columns in dataframe.

    Parameters
    ----------
    data: DataFrame
        Data frame containing values for calculating stats
    column_prefix:
        Prefix which should be added to column names for summary stats

    Returns
    --------
    data: DataFrame
        Data frame object containing additional columns with statistics
    """
    if not column_prefix:
        column_prefix = ''
    else:
        column_prefix = '{}_'.format(column_prefix)

    stats_df = DataFrame(data=data)
    stats = calculate_stats(data)
    stats_df['{}min'.format(column_prefix)] = stats.min
    stats_df['{}max'.format(column_prefix)] = stats.max
    stats_df['{}sum'.format(column_prefix)] = stats.sum
    stats_df['{}mean'.format(column_prefix)] = stats.mean
    stats_df['{}std'.format(column_prefix)] = stats.std
    stats_df['{}p25'.format(column_prefix)] = stats.p25
    stats_df['{}p50'.format(column_prefix)] = stats.p50
    stats_df['{}p75'.format(column_prefix)] = stats.p75
    stats_df['{}p50'.format(column_prefix)] = stats.p90
    stats_df['{}iqr'.format(column_prefix)] = stats.iqr
    stats_df['{}entropy'.format(column_prefix)] = stats.entropy

    return stats_df


def calculate_stats(data: DATA_VECTOR) -> Munch:
    """ Calculate summary statistics including sum, min, max, mean, 25/50/75/90 percentile, IQR, standard deviation,
    and entropy.

    Parameters
    ----------
    data: DATA_VECTOR
        List of integer or float values to calculate the sum.

    Returns
    -------
    stats: Munch
        JSON (dictionary, munch) object containing statistics calculated from data.
    """
    stats = DefaultMunch(0)
    if not data or not isinstance(data, (list, ndarray)):
        return stats

    if isinstance(data, list):
        data = np.array(data)

    stats.max = np.max(data)
    stats.min = np.min(data)
    stats.sum = np.sum(data)
    stats.mean = np.mean(data)
    stats.std = np.std(data)
    stats.p25, stats.p50, stats.p75, stats.p90 = calculate_quantiles(data, percentiles=[25, 50, 75, 90])
    stats.iqr = stats.p75 - stats.p25
    stats.entropy = calculate_entropy(data)

    return stats
