#! /bin/bash

debug=true

# Function to find minimum degree bits that works
find_min_degree_bits() {
    local num_levels=$1
    local num_checkpoint_updates=$2
    local estimate_degree_bits=$3
    
    # Validate arguments
    if [ -z "$num_levels" ] || [ -z "$num_checkpoint_updates" ]; then
        echo "Usage: find_min_degree_bits <num_levels> <num_checkpoint_updates>"
        return 1
    fi
    
    num_failures=0
    while true; do
        cargo run --release -- -l $num_levels -c $num_checkpoint_updates -g $estimate_degree_bits -b > /dev/null 2>&1

        if [ $? -eq 0 ]; then
            break
        fi
        num_failures=$((num_failures+1))
        if [ $num_failures -eq 2 ]; then
            echo "Failed 2 times in a row. Exiting." >&2
            exit 0
        fi
        estimate_degree_bits=$((estimate_degree_bits + 1))
    done
    if $debug; then
        echo "Degree bits: $num_checkpoint_updates $estimate_degree_bits" >&2
    fi
    echo $estimate_degree_bits
    return
}

find_change_point_sequentially() {
    echo "Finding change point starting from $2 for 2**$4 gates" >&2
    local num_levels=$1
    local start_updates=$2
    local step=$3
    local estimate=$4

    # Break when the degree bits change
    local prev_bits=$(find_min_degree_bits $num_levels $start_updates $estimate)
    # Assert that estimate is equal to prev_bits
    if [ $estimate -ne $prev_bits ]; then
        echo "Estimate is not equal to prev_bits" >&2
        exit 1
    fi
    local num_checkpoint_updates=$((start_updates+step))
    while true; do
        bits=$(find_min_degree_bits $num_levels $num_checkpoint_updates $estimate)
        if [ $prev_bits -ne $bits ]; then
            echo $((num_checkpoint_updates-step))
            return 
        fi
        num_checkpoint_updates=$((num_checkpoint_updates+step))
    done
}

# Take num levels as argument
num_levels=$1
cur_gates=14
cur_updates=50
step=50
# TODO: Building the circuit is failing at 2**18 gates. Investigate why.
end_gates=18

while true; do
    change_point=$(find_change_point_sequentially $num_levels $cur_updates $step $cur_gates)
    echo "Change point:" $change_point $cur_gates
    cur_updates=$((change_point+step))
    cur_updates=$((cur_updates*2))
    cur_gates=$((cur_gates+1))
    if [ $cur_gates -eq $end_gates ]; then
        break
    fi
done
