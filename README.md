# Traffic Analysis Tools
This repository contains scripts used for analyzing **.pcap* files obtained from IoT devices.

## Dependencies
```bash
$ pip install -r requirements.txt
```

## Documentation
To generate documentation from repo, please perform following steps
```bash
$ cd docs           # Docs root directory
$ make clean        # Remove outdated docs files
$ make html         # Generate HTML documentation
$ make view-docs    # Opens docs in Firefox
``` 

## Scripts
### Required scripts
* Script for parsing pcap files and extract features per packet from the pcap, to a csv file
