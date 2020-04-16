import math
import numpy
import random
import string


def id_generator(length: int = 8) -> str:
    """
    Generates a random string consisting of upper case characters and digits.
    e.g. 6U1S75, 4Z4UKK, U911K4
    :param: length of id (default=8)
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def generate_secret_key(length: int = 32):
    """
    Generates a secret key consisting of ascii characters, special characters and digits.
    for example IG0Z[00;QEq;Iy.sZp8>16dv)reQ(R8z
    :param: length of key (default=32)
    """
    return ''.join(random.choice(string.ascii_letters + string.digits + '!@#$%^&*().,;:[]{}<>?') for _ in range(length))


def extract_stats(data: list = None):
    """
    This function receives a list of data and generates number of statistical
    values from this data. The function is (instead of using built-ins) to
    reduce time complexity by doing one pass over the data.
    :param data: list of data points
    :return: Dictionary object containing sum, minimum, maximum, mean, median,
    mode, standard_deviation, variance, quartile, decile.
    """
    if not data:
        return {}

    # FIXME: rewrite this function to make it more economical in time-complexity
    data = sorted(data)
    results = dict(
        count=len(data),
        sum=sum(data),
        var=numpy.var(data),
        range=data[-1] - data[0]
    )
    results["stdev"] = math.sqrt(results.get("var"))
    results["mean"] = results.get("sum")/results.get("count")
    results["pentile"] = list(numpy.percentile(data, numpy.arange(0, 100, 5))) + [data[-1]]

    return results
