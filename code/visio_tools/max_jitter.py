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
    "xtick.labelsize": 9,
    "ytick.labelsize": 10,
    "legend.fontsize": 11,
    "lines.linewidth": 1.3,
    "lines.markersize": 6,
    "grid.alpha": 0.4,
})

# -------------------------
# Funktion zum Einlesen einer Config
# -------------------------
def read_jitter(base_dir):
    data = {}
    for root, dirs, files in os.walk(base_dir):
        if "latencys_0" in files:
            path = os.path.join(root, "latencys_0")
            parts = path.split(os.sep)

            std = parts[2].split("_")[1]
            freq = parts[3].split("_")[1]
            bw = parts[4].split("_")[1]
            qos = parts[5].split("_")[1]
            proto = parts[6].lower()

            key = f"{std}-{freq}-{bw}-{qos}-{proto}"

            rtts = []
            with open(path, "r") as f:
                for line in f:
                    try:
                        numbers = list(map(int, line.strip().split(",")))
                        rtts.append(numbers[-1])
                    except ValueError:
                        continue

            if len(rtts) > 1:
                rtts = [v for v in rtts if v < 1e8]
                if len(rtts) < 2:
                    continue
                diffs = [abs(rtts[i] - rtts[i-1]) / 1e3 for i in range(1, len(rtts))]  # ns→µs
                max_jitter = (max(rtts) - min(rtts)) / 1e3 if rtts else np.nan
                avg_jitter = np.mean(diffs) if diffs else np.nan
                data[key] = {"max": max_jitter, "avg": avg_jitter}
    return data

# -------------------------
# Zwei Configs abfragen
# -------------------------
config_x = input("Config X (z. B. 1): ").strip()
config_y = input("Config Y (z. B. 2): ").strip()

data_x = read_jitter(config_x + "/results")
data_y = read_jitter(config_y + "/results")

# -------------------------
# Nur Keys aus Config X auf der X-Achse
# -------------------------
x_labels = sorted(data_x.keys())
x = np.arange(len(x_labels))

max_x = [data_x[k]["max"] for k in x_labels]
avg_x = [data_x[k]["avg"] for k in x_labels]
max_y = [data_y.get(k, {}).get("max", np.nan) for k in x_labels]
avg_y = [data_y.get(k, {}).get("avg", np.nan) for k in x_labels]

# -------------------------
# Plot erstellen
# -------------------------
fig, ax = plt.subplots(figsize=(15, 7))

# Config X
ax.plot(x, max_x, "o-", color="tab:blue", label=f"Config {config_x} – Max Jitter")
ax.plot(x, avg_x, "s--", color="tab:green", label=f"Config {config_x} – Avg Jitter")

# Config Y
ax.plot(x, max_y, "o-", color="tab:orange", label=f"Config {config_y} – Max Jitter")
ax.plot(x, avg_y, "s--", color="tab:red", label=f"Config {config_y} – Avg Jitter")

# Achsen
ax.set_xticks(x)
ax.set_xticklabels(x_labels, rotation=90)
ax.set_ylabel("Jitter (µs)")
ax.set_title(f"Vergleich: Jitter für Config {config_x} und Config {config_y}")
ax.grid(True, linestyle=":", linewidth=0.7)

# Legende mit klaren Symbolen
legend_handles = [
    Line2D([], [], color="tab:blue", marker="o", linestyle="-", label=f"Config {config_x} – Max Jitter"),
    Line2D([], [], color="tab:green", marker="s", linestyle="--", label=f"Config {config_x} – Avg Jitter"),
    Line2D([], [], color="tab:orange", marker="o", linestyle="-", label=f"Config {config_y} – Max Jitter"),
    Line2D([], [], color="tab:red", marker="s", linestyle="--", label=f"Config {config_y} – Avg Jitter"),
]
ax.legend(handles=legend_handles, loc="best")

plt.tight_layout()
plt.savefig(f"jitter_comparison_{config_x}_vs_{config_y}_keys_from_{config_x}.pdf")
plt.savefig(f"jitter_comparison_{config_x}_vs_{config_y}_keys_from_{config_x}.png")
plt.close()

print(f"Fertig! Jittervergleich für Config {config_x} (Baseline) und {config_y} gespeichert – nur Keys aus {config_x}.")
