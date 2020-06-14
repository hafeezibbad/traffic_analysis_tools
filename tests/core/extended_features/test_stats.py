import unittest

from core.extended_features.stats import make_bins, calculate_entropy, calculate_entropy_using_scipy, \
    calculate_entropy_using_numpy, calculate_quantiles, calculate_stats, calculate_stats_over_n_items
from tests.fixtures.extracted_features.stats import TEST_DATA_VECTOR, BINNED_TEST_DATA_VECTOR, UNEVEN_INPUT_DATA, \
    BINNED_UNEVEN_DATA, TEST_DATA_ENTROPY, QUARTILES_RESULT, CUSTOM_QUANTILES, MISORDERED_PERCENTILE, \
    MISORDERED_QUANTILE_RESULT, CUSTOM_PERCENTILE, QUARTILES_INPUT, TEST_DATA_STATS


class StatsTests(unittest.TestCase):
    def test_make_bins_creates_equally_sized_bins_as_expected(self):
        binned_data = make_bins(TEST_DATA_VECTOR, 3)
        self.assertEqual(4, len(binned_data))
        self.assertEqual(BINNED_TEST_DATA_VECTOR, binned_data)

    def test_make_bins_create_uneven_bins_as_expected(self):
        binned_data = make_bins(UNEVEN_INPUT_DATA, 3)
        self.assertEqual(5, len(binned_data))
        self.assertEqual(BINNED_UNEVEN_DATA, binned_data)

    def test_calculate_entropy_using_scipy_works_as_expected(self):
        entropy = calculate_entropy_using_scipy(TEST_DATA_VECTOR)
        self.assertAlmostEqual(TEST_DATA_ENTROPY, entropy, places=7)

    def test_calculate_entropy_using_numpy_works_as_expected(self):
        entropy = calculate_entropy_using_numpy(TEST_DATA_VECTOR)
        self.assertAlmostEqual(TEST_DATA_ENTROPY, entropy, places=7)

    def test_calculate_entropy_using_numpy_or_scipy_returns_same_result(self):
        entropy_numpy = calculate_entropy_using_numpy(TEST_DATA_VECTOR)
        entropy_scipy = calculate_entropy_using_scipy(TEST_DATA_VECTOR)
        self.assertAlmostEqual(TEST_DATA_ENTROPY, entropy_scipy, places=7)
        self.assertAlmostEqual(TEST_DATA_ENTROPY, entropy_numpy, places=7)
        self.assertAlmostEqual(entropy_numpy, entropy_scipy, places=7)

    def test_calculate_entropy_works_as_expected(self):
        entropy = calculate_entropy(TEST_DATA_VECTOR)
        self.assertAlmostEqual(TEST_DATA_ENTROPY, entropy, places=7)

    def test_calculate_quantiles_works_as_expected(self):
        quartiles = calculate_quantiles(TEST_DATA_VECTOR, percentiles=QUARTILES_INPUT)
        self.assertEqual(3, len(quartiles))
        self.assertEqual(QUARTILES_RESULT, list(quartiles))

    def test_calculate_quantiles_works_as_expected_with_default_values(self):
        quartiles = calculate_quantiles(TEST_DATA_VECTOR)
        self.assertEqual(3, len(quartiles))
        self.assertEqual(QUARTILES_RESULT, list(quartiles))

    def test_calculate_quantiles_works_as_expected_when_input_percentile_are_empty(self):
        quartiles = calculate_quantiles(TEST_DATA_VECTOR, percentiles=[])
        self.assertEqual(3, len(quartiles))
        self.assertEqual(QUARTILES_RESULT, list(quartiles))

    def test_calculate_quantiles_works_with_custom_percentiles(self):
        quantiles = calculate_quantiles(TEST_DATA_VECTOR, percentiles=CUSTOM_PERCENTILE)
        self.assertEqual(4, len(quantiles))
        self.assertEqual(CUSTOM_QUANTILES, list(quantiles))

    def test_order_matters_with_custom_percentiles_in_calculate_quantile(self):
        quantiles = calculate_quantiles(TEST_DATA_VECTOR, percentiles=MISORDERED_PERCENTILE)
        self.assertEqual(4, len(quantiles))
        self.assertEqual(MISORDERED_QUANTILE_RESULT, list(quantiles))

    def test_calculate_stats_returns_empty_stats_if_no_data_is_provided(self):
        stats = calculate_stats()
        for k, v in stats.items():
            self.assertEqual(v, 0)

    def test_calculate_stats_returns_empty_stats_if_data_is_none(self):
        stats = calculate_stats(data=None)
        for k, v in stats.items():
            self.assertEqual(v, 0)

    def test_calculate_stats_returns_empty_stats_if_data_is_not_an_array(self):
        stats = calculate_stats(data=123)
        for k, v in stats.items():
            self.assertEqual(v, 0)

    def test_calculate_stats_works_as_expected(self):
        stats = calculate_stats(data=TEST_DATA_VECTOR)
        for k, v in stats.items():
            self.assertAlmostEqual(TEST_DATA_STATS[k], v, places=7)

    def test_summary_stat_are_returned_if_n_items_is_more_than_data_len(self):
        stats = calculate_stats_over_n_items(data=TEST_DATA_VECTOR, n_items=15)
        for k, b in stats.items():
            self.assertAlmostEqual(TEST_DATA_STATS[k], v, places=7)
