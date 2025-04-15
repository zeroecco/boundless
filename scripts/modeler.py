#!/usr/bin/env python3

import math
import json
import os

def get_benchmark_data():
    try:
        # Read the JSON file
        with open('output.json', 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print("Error: output.json file not found. Please run the benchmark first.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing output.json: {e}")
        return None

def extract_throughput(data, operation_name):
    for item in data:
        if item['name'] == operation_name:
            return item['throughput']
    return None

# Get benchmark data
benchmark_data = get_benchmark_data()

# --- Inputs & Assumptions ---
eth_block_time = 12  # Target time window in seconds (Ethereum block time)
estimated_total_cycles = 400_000_000  # Estimated total cycles required within the window
segment_size = 2**21
recursion_size = 2**18
# Component Durations (in cycles)
# Use benchmark data if available, otherwise use defaults
if benchmark_data:
    exec_hz = extract_throughput(benchmark_data, 'execute')
    single_proof_hz = extract_throughput(benchmark_data, 'succinct')
    single_lift_hz = extract_throughput(benchmark_data, 'lift')
    single_join_hz = extract_throughput(benchmark_data, 'join')
    resolve_hz = extract_throughput(benchmark_data, 'succinct')  # Using succinct for resolve as well

    # Print debug information about the values we found
    print("\nBenchmark Data:")
    print(f"Execute throughput: {exec_hz:,.2f} cycles/second")
    print(f"Succinct throughput: {single_proof_hz:,.2f} cycles/second")
    print(f"Lift throughput: {single_lift_hz:,.2f} cycles/second")
    print(f"Join throughput: {single_join_hz:,.2f} cycles/second")
    print(f"Resolve throughput: {resolve_hz:,.2f} cycles/second")
else:
    exec_hz = 25_000_000
    single_proof_hz = 839_000
    single_lift_hz = 648_000
    single_join_hz = 431_000
    resolve_hz = 839_000

# component durations in seconds
exec_duration = round(estimated_total_cycles / exec_hz, 3)
single_proof_duration = round(segment_size / single_proof_hz, 3)
single_lift_duration = round(recursion_size / single_lift_hz, 3)
single_join_duration = round(recursion_size / single_join_hz, 3)
resolve_duration = round(recursion_size / resolve_hz, 3)

# --- Calculations ---

# Calculate the required processing speed (Hz) to meet the target time
required_effective_hz = math.ceil(estimated_total_cycles / eth_block_time)

# Calculate the number of segments the total work is divided into
num_segments = math.ceil(estimated_total_cycles / segment_size)

# Calculate the depth of the binary tree needed to join all segments
# Each level of the tree represents a joining step
binary_tree_depth = math.ceil(math.log2(num_segments)) if num_segments > 0 else 0

# Calculate the total cycles consumed by the modeled sequence of operations
total_cycles_per_operation = (
    exec_duration +
    single_proof_duration +
    single_lift_duration +
    (binary_tree_depth * single_join_duration) +
    resolve_duration
)

# --- Reporting ---
print("Processing Performance Modeling Report")
print("-"*60)
print("\nInputs & Assumptions:")
print(f"*   Target Time Window (Block Time): {eth_block_time} seconds")
print(f"*   Estimated Total Cycles Required: {estimated_total_cycles:,} cycles")
print(f"*   Required Processing Speed:       { math.ceil(required_effective_hz):,} cycles/second (Hz).")
print(f"*   Work Segmentation Size:          {segment_size:,} cycles per segment")
print(f"*   Recursion Size:                  {recursion_size:,} cycles per recursion")
print("-"*60)
print(f"*   Execution Phase:         {round(exec_hz):,}")
print(f"*   Single Proof Generation: {round(single_proof_hz):,}")
print(f"*   Single Lift Operation:   {round(single_lift_hz):,}")
print(f"*   Single Join Operation:   {round(single_join_hz):,}")
print(f"*   Resolve Phase:           {round(resolve_hz):,}")
print("-"*60)
print("\nCalculations:")
print(f"*   Number of Segments to Process: {num_segments:,}")
print(f"*   Number of Joins to Process: {num_segments - 1:,}")
print(f"*   Required Processing Speed: {math.ceil(required_effective_hz):,} cycles/second (Hz).")
print(f"*   Binary Tree Depth for Joins:   Joining {num_segments:,} segments requires {binary_tree_depth} levels.")

print("\nTotal cycles/second for Modeled Operation Sequence:")
print(f"    Execution:                    {exec_duration:15.3f} seconds")
print(f"    Single Proof:                 {single_proof_duration:15.3f} seconds")
print(f"    Single Lift:                  {single_lift_duration:15.3f} seconds")
print(f"    Joins ({binary_tree_depth} levels x {single_join_duration:.3f}sec):  {binary_tree_depth * single_join_duration:15.3f} seconds")
print(f"    Resolve:                      {resolve_duration:15.3f} seconds")
print("-"*60)
print(f"    Theoretical walltime:         {round(total_cycles_per_operation, 3):15.3f} seconds")

print("\nAnalysis:")
print(f"*  The modeled wall time based on the observed component durations is {round(total_cycles_per_operation, 3):.3f} seconds ")

