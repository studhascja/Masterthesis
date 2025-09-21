import os
import numpy as np
import matplotlib.pyplot as plt

for i in range(3):
    config = str(i + 1)
    BASE_DIR = config + "/results"
    
    # Dict: Testname -> (Liste von Jitter-Werten, Protokoll)
    jitter_data = {}
    latency_data = {}

    for root, dirs, files in os.walk(BASE_DIR):
        for file in files:
            if file == "latencys_0":
                path = os.path.join(root, file)
                parts = path.split(os.sep)
                # Erwartet: results/standard_X/frequency_Y/bandwith_Z/qos_W/{tcp,udp}/latencys_0
                std = parts[2].split("_")[1]
                freq = parts[3].split("_")[1]
                bw = parts[4].split("_")[1]
                qos = parts[5].split("_")[1]
                proto = parts[6]
                test_name = f"{std}-{freq}-{bw}-{qos}-{proto}"

                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])
                        except ValueError:
                            continue

                latency_data[test_name] = (rtts, proto)

                if len(rtts) > 1:
                    diffs = [abs(rtts[i] - rtts[i - 1]) / 1e3 for i in range(1, len(rtts))]  # ns → µs
                    jitter_data[test_name] = (diffs, proto)

    # --- Boxplot Jitter ---
    labels = list(jitter_data.keys())
    data = [vals for (vals, proto) in jitter_data.values()]
    protocols = [proto for (vals, proto) in jitter_data.values()]

    plt.figure(figsize=(12, 6))
    box = plt.boxplot(data, vert=True, patch_artist=True)

    # Farben nach Protokoll
    for patch, proto in zip(box['boxes'], protocols):
        if proto.lower() == "tcp":
            patch.set_facecolor("skyblue")
        else:
            patch.set_facecolor("lightgreen")

    plt.xticks(range(1, len(labels) + 1), labels, rotation=90, fontsize=8)
    plt.ylabel("Jitter (µs)")
    plt.title(f"Jitter pro Testfall")
    plt.tight_layout()

    plt.savefig(f"jitter_boxplot_{config}.pgf")
    plt.savefig(f"jitter_boxplot_{config}.png")
    plt.close()

    # --- Boxplot Latency ---
    data_latency = [vals for (vals, proto) in latency_data.values()]

    plt.figure(figsize=(12, 6))
    box = plt.boxplot(data_latency, vert=True, patch_artist=True)

    # Farben nach Protokoll
    for patch, proto in zip(box['boxes'], protocols):
        if proto.lower() == "tcp":
            patch.set_facecolor("skyblue")
        else:
            patch.set_facecolor("lightgreen")

    plt.xticks(range(1, len(labels) + 1), labels, rotation=90, fontsize=8)
    plt.ylabel("Latency (ms)")
    plt.title(f"Latency pro Testfall)")
    plt.tight_layout()

    plt.savefig(f"latency_boxplot_{config}.pgf")
    plt.savefig(f"latency_boxplot_{config}.png")
    plt.close()

    print(f"Fertig! Boxplots für Testlauf {BASE_DIR} erzeugt.")
