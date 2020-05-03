from math import log, e
from typing import Union, List

from pandas import DataFrame
from scipy.stats import entropy
from numpy import ndarray
import numpy as np

from core.extended_features import DATA_VECTOR


def calculate_entropy(data: DATA_VECTOR) -> float:
    return calculate_entropy_using_numpy(data)  # Use faster method


# Fastest method
def calculate_entropy_using_numpy(data: DATA_VECTOR, base=None) -> float:
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

    entropy = 0

    base = e if base is None else base
    for i in probabilities:
        entropy -= i * log(i, base)

    return entropy


# Simplest method to calculate entropy
def calculate_entropy_using_scipy(data: DATA_VECTOR, base=None):
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


def calculate_quantiles(data: DATA_VECTOR, percentiles: List[int] = None) -> Union[int, float, complex, ndarray]:
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


def make_bins(data: DATA_VECTOR, n_items: int) -> DATA_VECTOR:
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
