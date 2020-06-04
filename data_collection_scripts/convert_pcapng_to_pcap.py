#!/usr/bin/python

# This script converts pcapng files to pcap format. In some cases, pcap files saved from 
# Wireshark are of pcapng format. Therefore, they need to be converted to pcap before we 
# can process the files


import os
import time 

dir_path = os.path.join(os.getcwd(), 'input_folder')
file_list = os.listdir(dir_path)
pcap_files = [fp for fp in file_list if fp.endswith('.pcap')]
output_dir_path = os.path.abspath(os.path.join(os.getcwd(), 'output folder'))
cmd  = 'editcap {input_fp} {output_fp} -F pcap'
for f in pcap_files:
    start_time = time.time()
    input_fp = os.path.join(dir_path, f)
    output_fp = os.path.join(output_dir_path, os.path.basename(f))
    os.system(cmd.format(input_fp=input_fp, output_fp=output_fp))
    print('File written: ', output_fp)
    print('Time taken: {} (s)'.format(time.time()-start_time))
    print('-'  * 80)
