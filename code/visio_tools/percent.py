import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

# -------------------------
# LaTeX-ähnlicher Style
# -------------------------
plt.rcParams.update({
    "font.family": "serif",
    "font.weight": "bold",
    "axes.labelweight": "bold",
    "axes.titleweight": "bold",
    "font.size": 12,
    "axes.labelsize": 13,
    "axes.titlesize": 15,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 11,
    "lines.linewidth": 1.2,
    "lines.markersize": 5,
    "grid.alpha": 0.4,
})

# -------------------------
# Daten einlesen
# -------------------------
all_latency_data = {}

for i in range(3):
    config = str(i + 1)
    BASE_DIR = config + "/results"

    for root, dirs, files in os.walk(BASE_DIR):
        for file in files:
            if file == "latencys_0":
                path = os.path.join(root, file)
                parts = path.split(os.sep)
                std = parts[2].split("_")[1]
                freq = parts[3].split("_")[1]
                bw = parts[4].split("_")[1]
                qos = parts[5].split("_")[1]
                proto = parts[6].lower()

                test_key = f"{std}-{freq}-{bw}"  # ohne QoS und Proto
                group_key = (test_key, proto, qos)

                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])
                        except ValueError:
                            continue

                if len(rtts) > 1:
                    all_latency_data.setdefault(group_key, []).append(rtts)

# -------------------------
# Jitter berechnen
# -------------------------
jitter_stats = {}
for (test_key, proto, qos), runs in all_latency_data.items():
    max_vals, avg_vals = [], []
    for rtts in runs:
        rtts = [v for v in rtts if v < 1e8]
        if len(rtts) < 2:
            continue
        diffs = [abs(rtts[i] - rtts[i-1]) / 1e3 for i in range(1, len(rtts))]
        max_vals.append((max(rtts) - min(rtts)) / 1e3)
        avg_vals.append(np.mean(diffs) if diffs else np.nan)

    if max_vals and avg_vals:
        jitter_stats[(test_key, proto, qos)] = {
            "max": np.nanmax(max_vals),
            "avg": np.nanmean(avg_vals)
        }

# -------------------------
# X-Achse vorbereiten: Testcases nach proto/qos
# -------------------------
x_labels = sorted({f"{k[1].upper()} {'QoS' if k[2]=='1' else 'no QoS'}" for k in jitter_stats.keys()})
x = np.arange(len(x_labels))

def get_curve(mode):
    """Gibt die Jitter-Werte für alle X-Labels zurück."""
    values = []
    for lbl in x_labels:
        proto, qos = lbl.split()[0].lower(), '1' if 'QoS' in lbl else '0'
        val_list = [v[mode] for (k_test, k_proto, k_qos), v in jitter_stats.items() if k_proto == proto and k_qos == qos]
        values.append(np.nanmean(val_list) if val_list else np.nan)
    return values

# -------------------------
# Plot erstellen
# -------------------------
fig, ax = plt.subplots(figsize=(14, 7))

max_vals = get_curve("max")
avg_vals = get_curve("avg")

ax.plot(x, max_vals, marker="o", linestyle="-", color="tab:blue", label="Maximaler Jitter")
ax.plot(x, avg_vals, marker="s", linestyle="--", color="tab:green", label="Durchschnittlicher Jitter")

ax.set_xticks(x)
ax.set_xticklabels(x_labels, rotation=45, ha="right")
ax.set_ylabel("Jitter (µs)")
ax.set_title("Maximaler und durchschnittlicher Jitter pro Protokoll / QoS")
ax.grid(True, linestyle=":", linewidth=0.7)

ax.legend()
plt.tight_layout()
plt.savefig("jitter_all_in_one.pdf")
plt.savefig("jitter_all_in_one.png")
plt.close()

print("Fertig! Max- und Avg-Jitter wurden in einer Datei erstellt.")
