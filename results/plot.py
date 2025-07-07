import os
import csv
import matplotlib.pyplot as plt
import numpy as np


def read_throughput_values(csv_path):
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        next(reader)
        return [float(row[1]) for row in reader if len(row) >= 2]


def read_latency_values(csv_path):
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        next(reader)
        p50_list, p90_list = [], []
        for row in reader:
            if len(row) >= 3:
                p50_list.append(float(row[1]))
                p90_list.append(float(row[2]))
        return p50_list, p90_list


def process_folders(folder_list):
    data = []
    for folder in folder_list:
        tps_path = os.path.join(folder, "end-to-end-tps.csv")
        latency_path = os.path.join(folder, "end-to-end-latency.csv")

        if not os.path.exists(tps_path) or not os.path.exists(latency_path):
            print(f"Skipping {folder}: missing file.")
            continue

        try:
            tps = read_throughput_values(tps_path)
            p50, p90 = read_latency_values(latency_path)
            data.append((folder, np.mean(tps), np.mean(p50), np.mean(p90)))
        except Exception as e:
            print(f"Error processing {folder}: {e}")
    return data


def plot_latency_vs_throughput(data, output_prefix="latency_vs_throughput"):
    labels = [item[0] for item in data]
    throughputs = [item[1] for item in data]
    p50s = [item[2] for item in data]
    top_errors = [item[3] - item[2] for item in data]
    bottom_errors = [0 for _ in top_errors]

    asymmetric_errors = [bottom_errors, top_errors]

    plt.figure(figsize=(9, 6))
    plt.errorbar(
        throughputs,
        p50s,
        yerr=asymmetric_errors,
        fmt="o",
        capsize=5,
        color="blue",
        ecolor="gray",
    )

    for i, label in enumerate(labels):
        plt.annotate(
            label,
            (throughputs[i], p50s[i]),
            textcoords="offset points",
            xytext=(5, 5),
            fontsize=8,
        )

    plt.title("Latency (P50 + P90) vs Throughput")
    plt.xlabel("Throughput (TPS)")
    plt.ylabel("Latency (ms)")
    plt.ylim(bottom=0)  # Force y-axis to start at 0
    plt.grid(True)
    plt.tight_layout()

    # Save to PDF and PNG
    plt.savefig(f"{output_prefix}.pdf")
    plt.savefig(f"{output_prefix}.png", dpi=300)
    plt.close()
    print(f"Saved plot to {output_prefix}.pdf and {output_prefix}.png")


if __name__ == "__main__":
    folders = ["5-1-600-30-25-9-3-1", "5-1-600-30-25-9-3-2", "5-1-600-30-25-9-3-3"]

    results = process_folders(folders)
    if results:
        plot_latency_vs_throughput(results)
    else:
        print("No valid data to plot.")
