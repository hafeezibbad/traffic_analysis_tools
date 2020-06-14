from math import log, e
from typing import Union, List

from munch import Munch, DefaultMunch
from pandas import DataFrame
from scipy.stats import entropy
from numpy import ndarray
import numpy as np
import pandas as pd

from core.extended_features import DATA_VECTOR_TYPE


def calculate_entropy(data: DATA_VECTOR_TYPE) -> float:
    return calculate_entropy_using_numpy(data)  # Use faster method


# Fastest method
def calculate_entropy_using_numpy(data: DATA_VECTOR_TYPE, base=None) -> float:
    """Calculate entropy of a given set of values using numpy and math.

    Reference: https://stackoverflow.com/a/45091961

    Parameters
    ----------
    data: List
        List of values (integer or float) to calculate entropy
    base: float
        Log function base

    Returns
    -------
    entropy: float
        Entropy of given set of values
    """
    n_items = len(data)
    if n_items <= 1:
        return 0

    values, counts = np.unique(data, return_counts=True)
    probabilities = counts / n_items
    n_classes = np.count_nonzero(probabilities)

    if n_classes <= 1:
        return 0

    _entropy = 0

    base = e if base is None else base
    for i in probabilities:
        _entropy -= i * log(i, base)

    return _entropy


# Simplest method to calculate entropy
def calculate_entropy_using_scipy(data: DATA_VECTOR_TYPE, base=None):
    """Calculate entropy of a given set of values using scipy.stats.entropy

    Reference: https://stackoverflow.com/a/45091961

    Parameters
    ----------
    data: List
        List of values (integer or float) to calculate entropy
    base: float
        Log function base

    Returns
    -------
    entropy: float
        Entropy of given set of values
    """
    value, counts = np.unique(data, return_counts=True)
    return entropy(counts, base=base)


def calculate_quantiles(data: DATA_VECTOR_TYPE, percentiles: List[int] = None) -> Union[int, float, complex, ndarray]:
    """Calculate quantiles on input data.

    Parameters
    ----------
    data: List[Union[int, float]]
        Input data, list of integer or float values, to calculate quantiles
    percentiles: List[int]
        List of (integer) percentiles to calculate. If no data is provided, only quartiles are calculated

    Returns
    -------
    quantile: DataFrame
        Data frame containing data for quantiles calculated from input data
    """
    if not percentiles:
        percentiles = [25, 50, 75]

    return np.percentile(data, percentiles)


def make_bins(data: DATA_VECTOR_TYPE, n_items: int) -> DATA_VECTOR_TYPE:
    """Divide input data vector to n bins where each bin contains n items. Last bucket may contain < n items.

    Parameters
    ----------
    data: DATA_VECTOR
        Data which should be divided into bins
    n_items: int
        Number of items in each bin

    Returns
    -------
    data: DATA_VECTOR[DATA_VECTOR]
        List of lists, with n items in each list
    """
    binned_data = []
    for i in range(0, (len(data) - len(data) % n_items), n_items):
        binned_data.append(data[i: i+n_items])

    i = i + n_items
    if i < len(data):
        binned_data.append(data[i:])

    return binned_data


def compile_data_frame_including_stats(data: DataFrame, column_prefix: str = None) -> DataFrame:
    """This function adds summary statistics as additional columns in data frame.

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
    stats_df['{}p90'.format(column_prefix)] = stats.p90
    stats_df['{}iqr'.format(column_prefix)] = stats.iqr
    stats_df['{}entropy'.format(column_prefix)] = stats.entropy

    return stats_df


def calculate_stats(data: DATA_VECTOR_TYPE = None) -> Munch:
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


def calculate_stats_over_n_items(data: DATA_VECTOR_TYPE, n_items: int = None) -> DataFrame:
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
