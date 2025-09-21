import os
import numpy as np
import matplotlib.pyplot as plt

BASE_DIR = "results"

# Dict: Testname -> (Liste von Jitter-Werten, Protokoll)
jitter_data = {}

for root, dirs, files in os.walk(BASE_DIR):
    for file in files:
        if file == "latencys_0":
            path = os.path.join(root, file)
            parts = path.split(os.sep)
            std = parts[1].split("_")[1]
            freq = parts[2].split("_")[1]
            bw = parts[3].split("_")[1]
            qos = parts[4].split("_")[1]
            proto = parts[5]
            test_name = f"{std}-{freq}-{bw}-{qos}-{proto}"

            rtts = []
            with open(path, "r") as f:
                for line in f:
                    try:
                        numbers = list(map(int, line.strip().split(",")))
                        rtts.append(numbers[-1])
                    except ValueError:
                        continue

            if len(rtts) > 1:
                diffs = [abs(rtts[i] - rtts[i-1]) / 1e3 for i in range(1, len(rtts))]  # ns → µs
                jitter_data[test_name] = (diffs, proto)

# --- Boxplot ---
labels = list(jitter_data.keys())
data = [vals for (vals, proto) in jitter_data.values()]
protocols = [proto for (vals, proto) in jitter_data.values()]

plt.figure(figsize=(12, 6))
box = plt.boxplot(data, vert=True, patch_artist=True, showfliers=False)

for patch, proto in zip(box['boxes'], protocols):
    if proto.lower() == "tcp":
        patch.set_facecolor("skyblue")
    else:
        patch.set_facecolor("lightgreen")

plt.xticks(range(1, len(labels) + 1), labels, rotation=90, fontsize=8)
plt.ylabel("Jitter (µs)")
plt.title("Jitter pro Testfall (Boxplot)")
plt.tight_layout()
plt.savefig("jitter_boxplot.pgf")
plt.savefig("jitter_boxplot.png")
plt.close()

# --- Scatterplot ---
markers = ["o", "s", "^", "D", "x", "P", "*", "v", "<", ">"]  # verschiedene Symbole
plt.figure(figsize=(12, 6))

for idx, (label, (vals, proto)) in enumerate(jitter_data.items()):
    marker = markers[idx % len(markers)]
    plt.scatter(range(len(vals)), vals, marker=marker, label=label,
                alpha=0.7, s=20)

plt.xlabel("Messung (Index)")
plt.ylabel("Jitter (µs)")
plt.title("Jitter Zeitverlauf pro Testfall (Scatter)")
plt.legend(fontsize=7, loc="upper right", ncol=2)
plt.tight_layout()
plt.savefig("jitter_scatter.pgf")
plt.savefig("jitter_scatter.png")
plt.close()

print("Fertig! Boxplot und Scatterplot gespeichert.")
