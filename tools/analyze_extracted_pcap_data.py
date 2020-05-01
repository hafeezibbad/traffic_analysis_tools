from pathlib import Path

import matplotlib.pyplot as plt
from munch import Munch
import pandas as pd
from pandas import DataFrame

from core.lib.converters import timestamp_to_formatted_date
from core.lib.matplotlib_utils import bar_plot
from tools.common import print_as_json

# Specify the path to directory which contains all data.
DATA_DIR_PATH = Path.home() / 'personal/phd/projects/traffic_analysis_tools/fixtures/results'
DATA_FILE_NAME = 'results.csv'
DATA_FILE_PATH = DATA_DIR_PATH / DATA_FILE_NAME

if DATA_FILE_PATH.exists() is False:
    print('The path specified for file containing data extracted from PCAP does not exist, please recheck')

# Load data file
pcap_data = pd.read_csv(str(DATA_FILE_PATH))

# Print header names
assert len(pcap_data.columns) == 81, 'Some columns are missing from csv file containing data from pcap file'

# Drop any columns which do not have any values
pcap_data = pcap_data.dropna(axis=1, how='all')
print(list(pcap_data.columns))

# Extract summary data from trace
summary_data = Munch()
summary_data.packet_count = pcap_data.shape[0]
summary_data.start_time = pcap_data['timestamp'].iloc[0]
summary_data.stop_time = pcap_data['timestamp'].iloc[-1]
summary_data.duration = summary_data.stop_time - summary_data.start_time
summary_data.packet_rate = summary_data.packet_count / summary_data.duration
summary_data.total_data = pcap_data['size'].sum()
summary_data.data_rate = summary_data.total_data/summary_data.duration
summary_data.average_packet_size = pcap_data['size'].mean()


print('Start time of trace: {}'.format(timestamp_to_formatted_date(summary_data.start_time)))
print('End time of trace: {}'.format(timestamp_to_formatted_date(summary_data.stop_time)))
print('Duration of trace: {} (seconds)'.format(summary_data.duration))
print('Total number of packets in trace: {}'.format(summary_data.packet_count))
print('Packet rate: {:.3f} (packets/second)'.format(summary_data.packet_rate))
print('Average packet size: {:.3f} (bytes)'.format(summary_data.packet_rate))
print('Total data transferred: {:.3f} (Megabytes)'.format(summary_data.total_data/1000000))
print('Data rate: {:.3f} (bytes/second)'.format(summary_data.data_rate))

# Unique IP addresses
summary_data.unique_src_ip = pcap_data['src_ip'].unique()
summary_data.unique_dst_ip = pcap_data['dst_ip'].unique()
summary_data.unique_ip = set().union(summary_data.unique_src_ip, summary_data.unique_dst_ip)


def get_protocol_specific_data(df: DataFrame, summary: Munch) -> Munch:
    proto_data = Munch()

    proto_data.count = df.shape[0]
    proto_data.total_data = df['size'].sum()
    proto_data.packet_rate = df.shape[0] / summary.duration
    proto_data.avg_packet_size = proto_data.total_data / (proto_data.count or 1)

    return proto_data


# Stats for outgoing packets
summary_data.outgoing_packets_data = get_protocol_specific_data(
    df=pcap_data[pcap_data['outgoing'] is True],
    summary=summary_data
)
print_as_json(summary_data.outgoing_packets_data)

# Stats for incoming packets
summary_data.incoming_packet_data = get_protocol_specific_data(
    df=pcap_data[pcap_data['outgoing'].isnull()],
    summary=summary_data
)
print_as_json(summary_data.incoming_packet_data)

# Unique layer 3 protocols
summary_data.unique_layer3_proto = pcap_data['eth_type'].unique()
layer3_proto_data = dict()
for proto in summary_data.unique_layer3_proto:
    layer3_proto_data[proto] = get_protocol_specific_data(
        df=pcap_data[pcap_data['eth_type'] == proto],
        summary=summary_data
    )
summary_data.layer3_proto_data = layer3_proto_data
print_as_json(summary_data.layer3_proto_data)
summary_data.unique_ip_ttl = pcap_data['ip_ttl'].unique()

# Unique layer 4 protocols
summary_data.unique_layer4_proto = pcap_data['ip_proto'].unique()
layer4_proto_data = dict()
for proto in summary_data.unique_layer4_proto:
    layer4_proto_data[proto] = get_protocol_specific_data(
        df=pcap_data[pcap_data['ip_proto'] == proto],
        summary=summary_data
    )
summary_data.layer4_proto_data = layer4_proto_data
print_as_json(summary_data.layer4_proto_data)


# Unique layer 7 protocols
summary_data.unique_layer7_proto = pcap_data['layer7_proto_name'].unique()
layer7_proto_data = dict()
for proto in summary_data.unique_layer7_proto:
    layer7_proto_data[proto] = get_protocol_specific_data(
        df=pcap_data[pcap_data['layer7_proto_name'] == proto],
        summary=summary_data
    )
summary_data.layer7_proto_data = layer7_proto_data
print_as_json(summary_data.layer7_proto_data)

# Data communicated to each IP Address
unique_ip = list(summary_data.unique_ip)
ips = []
data_sent = []
total_data = []
data_received = []
for ip in summary_data.unique_ip:
    if not ip:  # Ignore NaN values
        continue
    ips.append(ip)
    temp_df = pcap_data[(pcap_data['src_ip'] == ip) | (pcap_data['dst_ip'] == ip)]
    total_data.append(temp_df['size'].sum() / 1000)
    data_sent.append(temp_df[temp_df['dst_ip'] == ip]['size'].sum() / 1000)
    data_received.append(temp_df[temp_df['src_ip'] == ip]['size'].sum() / 1000)

data = {
    "Total Data": total_data,
    "Data Sent": data_sent,
    "Data Received": data_received
}

fig, ax = plt.subplots()
bar_plot(ax, data, total_width=0.8, single_width=0.9, legend=True)
ax.set_xticklabels(ips)
ax.set_ylabel('Data transferred (Kilobytes)')
ax.set_title('Data transferred per IP address')
plt.xticks(rotation=70)
plt.locator_params(axis='x', nbins=len(ips))
plt.show()
