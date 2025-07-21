import os
import csv
import matplotlib.pyplot as plt
import numpy as np
import re

# === Shared helpers ===


def read_column_values(csv_path):
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        headers = next(reader)
        rows = [row for row in reader if len(row) == len(headers)]
    return headers, rows


# === Latency vs Throughput plot ===


def read_throughput_values(csv_path, folder_name):
    parameters = folder_name.split("-")
    batch_size = parameters[4]
    num_batches_per_sub_bundle = parameters[5]
    branching_factor = parameters[6]
    num_compression_levels = parameters[7]

    multiplier = (
        int(batch_size)
        * int(num_batches_per_sub_bundle)
        * int(branching_factor) ** int(num_compression_levels)
    )

    _, rows = read_column_values(csv_path)
    return [float(row[1]) * multiplier for row in rows]


def read_latency_values(csv_path):
    _, rows = read_column_values(csv_path)
    p50s, p90s = [], []
    for row in rows:
        if len(row) >= 3:
            p50s.append(float(row[1]))
            p90s.append(float(row[2]))
    return p50s, p90s


def process_latency_throughput(folders):
    results = []
    for folder in folders:
        tps_path = os.path.join(folder, "end-to-end-tps.csv")
        latency_path = os.path.join(folder, "end-to-end-latency.csv")
        if not os.path.exists(tps_path) or not os.path.exists(latency_path):
            print(f"Missing TPS/latency file in {folder}")
            continue
        try:
            tps = read_throughput_values(tps_path, folder)
            p50, p90 = read_latency_values(latency_path)
            results.append((folder, np.median(tps), np.median(p50), np.median(p90)))
        except Exception as e:
            print(f"Error in {folder}: {e}")
    return results


def plot_latency_vs_throughput(data, output_prefix="latency_vs_throughput"):
    labels = [item[0] for item in data]
    throughputs = [item[1] for item in data]
    p50s = [item[2] for item in data]
    top_errors = [item[3] - item[2] for item in data]
    bottom_errors = [0] * len(data)

    plt.figure(figsize=(9, 6))
    plt.errorbar(
        throughputs,
        p50s,
        yerr=[bottom_errors, top_errors],
        fmt="o",
        capsize=5,
        color="blue",
        ecolor="gray",
    )

    for i, label in enumerate(labels):
        plt.annotate(
            label,
            (throughputs[i], p50s[i]),
            xytext=(5, 5),
            textcoords="offset points",
            fontsize=8,
        )

    plt.title("Latency (P50 + P90) vs Throughput")
    plt.xlabel("Throughput (updates/sec)")
    plt.ylabel("Latency (ms)")
    plt.ylim(bottom=0)
    plt.xlim(left=0)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{output_prefix}.pdf")
    plt.savefig(f"{output_prefix}.png", dpi=300)
    plt.close()
    print(f"[✓] Saved: {output_prefix}.pdf / .png")


# === Latency Breakdown Plot ===


def extract_p50_prover_names_and_indices(headers):
    """
    Returns a list of (prover_name, column_index) for P50 columns only.
    """
    pattern = r'prover="(.*?)"'  # Fix regex to two quotes
    prover_info = []
    for idx in range(1, len(headers), 2):  # P50 columns only (1, 3, ...)
        match = re.search(pattern, headers[idx])
        if match:
            prover_info.append((match.group(1), idx))
        else:
            prover_info.append((f"unknown_{idx}", idx))
    return prover_info


def process_prover_latency(folder):
    p50_data = {}  # prover_name -> list of p50 values

    for filename in ["primary-latency-breakdown.csv", "proxies-latency-breakdown.csv"]:
        path = os.path.join(folder, filename)
        if not os.path.exists(path):
            print(f"Missing file: {path}")
            continue

        print(f"Processing file: {path}")
        try:
            headers, rows = read_column_values(path)
            prover_info = extract_p50_prover_names_and_indices(headers)
            print(f"Found provers in {filename}: {[p[0] for p in prover_info]}")

            for prover_name, col_idx in prover_info:
                try:
                    values = [float(row[col_idx]) for row in rows]
                    if prover_name not in p50_data:
                        p50_data[prover_name] = []
                    p50_data[prover_name].extend(values)
                except Exception as e:
                    print(f"Error reading {prover_name} from {filename}: {e}")

        except Exception as e:
            print(f"Error processing {path}: {e}")

    summary = [
        (prover, np.median(values)) for prover, values in p50_data.items() if values
    ]
    print(f"Summary for folder {folder}: {summary}")
    return summary


def plot_prover_latency_breakdown(summary, folder_name):
    if not summary:
        print(f"No prover data to plot for {folder_name}")
        return

    summary.sort()
    provers = [s[0] for s in summary]
    p50s = [s[1] for s in summary]

    x = np.arange(len(provers))
    plt.figure(figsize=(10, 6))
    plt.bar(x, p50s, color="orange", edgecolor="black")
    plt.xticks(x, provers, rotation=45, ha="right")
    plt.title(f"Latency Breakdown by Prover\n{folder_name}")
    plt.xlabel("Prover")
    plt.ylabel("Average P50 Latency (ms)")
    plt.ylim(bottom=0)
    plt.tight_layout()
    prefix = f"prover_latency_breakdown_{folder_name}"
    plt.savefig(f"{prefix}.pdf")
    plt.savefig(f"{prefix}.png", dpi=300)
    plt.close()
    print(f"[✓] Saved: {prefix}.pdf / .png")


# === Main driver ===

if __name__ == "__main__":
    folders = ["4-1-180-30-50-4-3-1", "13-1-180-30-50-4-3-2", "13-1-180-30-50-4-3-3"]

    # Plot 1: Latency vs Throughput (combined)
    results = process_latency_throughput(folders)
    if results:
        plot_latency_vs_throughput(results)
    else:
        print("No valid latency-throughput data.")

    # Plot 2: One prover latency breakdown per folder
    for folder in folders:
        summary = process_prover_latency(folder)
        plot_prover_latency_breakdown(summary, folder)
