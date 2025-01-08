#! /bin/bash

# Function to find minimum degree bits that works
find_min_degree_bits() {
    local num_levels=$1
    local num_checkpoint_updates=$2
    local estimate_degree_bits=10
    
    # Validate arguments
    if [ -z "$num_levels" ] || [ -z "$num_checkpoint_updates" ]; then
        echo "Usage: find_min_degree_bits <num_levels> <num_checkpoint_updates>"
        return 1
    fi
    
    while true; do
        # Don't output anything
        cargo run --release -- -s $num_levels -c $num_checkpoint_updates -d $estimate_degree_bits -b > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break
        fi
        estimate_degree_bits=$((estimate_degree_bits + 1))
    done
    echo $estimate_degree_bits
    return $estimate_degree_bits
}

# bits=$(find_min_degree_bits 11 300)
# echo $bits

# Take num levels as argument
num_levels=$1

# Step through num checkpoint updates from 100 to 1000, in increments of 50
for num_checkpoint_updates in $(seq 100 50 1000); do
    bits=$(find_min_degree_bits $num_levels $num_checkpoint_updates)
    echo $num_checkpoint_updates $bits
done
