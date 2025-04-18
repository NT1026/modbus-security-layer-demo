#!/bin/bash

total=0
count=10
verbose=false

while getopts "vn:" opt; do
    case $opt in
        v)
            verbose=true
            ;;
        n)
            count=$OPTARG
            ;;
    esac
done

shift $((OPTIND - 1))

for i in $(seq 0 $count); do
    output=$(python3 $1 | grep "Packet sent in")
    time=$(echo $output | awk '/Packet sent in/ {print $4}')

    if [ "$i" -eq 0 ]; then
        continue
    fi

    total=$(echo "$total + $time" | bc)
    if [ "$verbose" = true ]; then
	    echo "[$i] $output"
    fi
done

average=$(echo "scale=4; $total / $count" | bc)

echo "Average: $average seconds"