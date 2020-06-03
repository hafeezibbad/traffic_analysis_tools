#!/bin/bash 


usage(){
    echo "Usage: $0 -p <file-prefix> -i <interface(s)> -t <timeout> -r <repetitions>"
    echo "  -p: Prefix for output file name (default:packet-capture)"
    echo "  -i: Identifier for interface(s) to run tcpdump. Multiple interfaces can be provided as comma-separated string"
    echo "  -t: timeout for running tcpdump (default=86400)"
    echo "  -r: Maximum iterations (default=99999, ~no limit)"
    echo "  -h: help"
    exit 1
}

timeout=86400
prefix="packet-capture"
interface=""
repetitions=9999
OIFS=$IFS

while getopts ":p:i:t:r:h" opt; do
    case ${opt} in
        p)
            prefix=$OPTARG
            ;;
        i)
            interface=("$OPTARG")
            ;;
        t)
            timeout=$OPTARG
            ;;
        r)
            repetitions=$OPTARG
            ;;
        h)
            usage
            ;;
        *)
            echo -e "Invalid Option: -$OPTARG\nCheck -h for usage instructions" 1>&2
            exit 1 
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then 
    echo "This script should run as root" 1>&2
    exit 2
fi

if [ -z "$interface" ]; then 
    echo "-i interface not provided for running tcpdump" 1>&2
    exit 1
fi


# Override IFS to convert comma-separated list of interfaces to array
# reference: https://bash.cyberciti.biz/guide/$IFS
IFS=","
interfaces=($interface)

# Uncomment following code to print the list of interfaces.
# for ((i=0; i<${#interfaces[@]}; ++i)); 
# do     
#     echo "interface $i: ${interfaces[$i]}"; 
# done

# restore original IFS
IFS=$OIFS

i=1
while [ $i -le $repetitions ]
do
    echo "Running repetition #$i"
    current_time=`date +%Y-%m-%d-%H-%M-%S`
    
    for intf in "${interfaces[@]}"
    do
        sudo timeout $timeout tcpdump -i ${intf} -s 65535 -w "${prefix}-${intf}-${current_time}.pcap" &
        sudo timeout $timeout tcpdump -i ${intf} -s 65535 -w "${prefix}-${intf}-${current_time}.pcap" &
    done
    # Since all processes are running in the background we need to pause execution for timeout period.
    sleep $timeout
    i=$[$i+1]
done
