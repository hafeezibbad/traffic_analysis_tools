from pathlib import Path
import os
import sys

from pandas import DataFrame

sys.path.append(os.getcwd())

from core.extended_features.time_based_feature_set import calculate_inter_arrival_time, \
    compile_data_frame_including_stats, calculate_stats, calculate_stats_over_n_items
from core.pandas_utils.dataframe_utils import load_csv_to_dataframe
from core.extended_features.stats import calculate_entropy, calculate_quantiles, make_bins

import time

items = [1, 3, 5, 2, 3, 5, 2, 1, 3, 4, 5, 3]

df = calculate_stats_over_n_items(items, n_items=4)
print(df.shape[0])
print(df.head(12))
# csv_path = Path('/home/hafeez/phd/projects/traffic_analysis_tools/fixtures/results/results.csv')
# data = load_csv_to_dataframe(csv_path)
# iat_data = calculate_inter_arrival_time(data)
# print(iat_data.shape[0])
# print(iat_data.head(10))