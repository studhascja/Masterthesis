import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend_handler import HandlerTuple

# -------------------------
# LaTeX-ähnlicher Style
# -------------------------
plt.rcParams.update({
    "font.family": "serif",
    "font.weight": "bold",      # alle Schriften fett
    "axes.labelweight": "bold", # Achsenbeschriftung fett
    "axes.titleweight": "bold", # Titel fett
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
# Configs auswählen
# -------------------------
config_x = input("Baseline Config (x): ").strip()
config_y = input("Vergleich Config (y): ").strip()
config_z = input("Vergleich Config (z, leer lassen wenn nicht gewünscht): ").strip()

def read_jitter(base_dir):
    """Liest maximale und mittlere Jitter-Werte für die Gesamtzeit aus einer Config ein."""
    data = {}
    for root, dirs, files in os.walk(base_dir):
        if "latencys_0" in files:
            path = os.path.join(root, "latencys_0")
            parts = path.split(os.sep)

            # Schlüssel: std, freq, bw, qos, proto
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
                        rtts.append(numbers[-1])  # nur Gesamtzeit
                    except ValueError:
                        continue

            if len(rtts) > 1:
                diffs = [abs(rtts[i] - rtts[i-1]) / 1e3 for i in range(1, len(rtts))]  # ns -> µs
                max_jitter = max(diffs) if diffs else 0
                avg_jitter = np.mean(diffs) if diffs else 0
                data[key] = {"max": max_jitter, "avg": avg_jitter, "qos": qos, "proto": proto}
    return data

# -------------------------
# Daten sammeln
# -------------------------
data_x = read_jitter(config_x + "/results")
data_y = read_jitter(config_y + "/results")
data_z = read_jitter(config_z + "/results") if config_z else None

# -------------------------
# Prozentuale Differenzen
# -------------------------
def calc_diffs(base, comp, proto_filter=None):
    diffs_max, diffs_avg, qos_flags, labels = [], [], [], []
    for key in base.keys():
        if key in comp:
            if proto_filter and not key.endswith(proto_filter):
                continue
            base_max, base_avg = base[key]["max"], base[key]["avg"]
            comp_max, comp_avg = comp[key]["max"], comp[key]["avg"]

            d_max = ((comp_max - base_max) / base_max * 100) if base_max > 0 else 0
            d_avg = ((comp_avg - base_avg) / base_avg * 100) if base_avg > 0 else 0

            labels.append(key)
            diffs_max.append(d_max)
            diffs_avg.append(d_avg)
            qos_flags.append(base[key]["qos"] == "1")
    return labels, diffs_max, diffs_avg, qos_flags

# -------------------------
# Plot Funktion (ein Plot pro Protokoll)
# -------------------------
def make_plot(proto):
    labels, diffs_max_y, diffs_avg_y, qos_flags = calc_diffs(data_x, data_y, proto_filter=proto)
    if data_z:
        _, diffs_max_z, diffs_avg_z, _ = calc_diffs(data_x, data_z, proto_filter=proto)

    if not labels:  # nichts zu plotten
        return

    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(11, 6))

    # Mittelwerte berechnen
    mean_y_max = np.mean(diffs_max_y) if diffs_max_y else 0
    mean_y_avg = np.mean(diffs_avg_y) if diffs_avg_y else 0
    line_mean_y_max = ax.axhline(mean_y_max, color="red", linestyle="-.", linewidth=2, label="Mean Max")
    line_mean_y_avg = ax.axhline(mean_y_avg, color="orange", linestyle="-.", linewidth=2, label="Mean Avg")

    # Linien für Config y
    ax.plot(x, diffs_max_y, "-", color="tab:blue", label=f"{config_y} vs {config_x} Max jitter")
    ax.plot(x, diffs_avg_y, "--", color="tab:green", label=f"{config_y} vs {config_x} Avg jitter")

    # Linien für Config z (falls vorhanden)
    if data_z:
        ax.plot(x, diffs_max_z, "-", color="tab:purple", label=f"{config_z} vs {config_x} Max jitter")
        ax.plot(x, diffs_avg_z, "--", color="tab:brown", label=f"{config_z} vs {config_x} Avg jitter")

    # Marker für QoS hervorheben
    for xi, dy, da, qos in zip(x, diffs_max_y, diffs_avg_y, qos_flags):
        ax.plot(xi, dy, "o", color="black" if qos else "white", markeredgecolor="tab:blue")
        ax.plot(xi, da, "s", color="black" if qos else "white", markeredgecolor="tab:green")

    if data_z:
        for xi, dy, da, qos in zip(x, diffs_max_z, diffs_avg_z, qos_flags):
            ax.plot(xi, dy, "o", color="black" if qos else "white", markeredgecolor="tab:purple")
            ax.plot(xi, da, "s", color="black" if qos else "white", markeredgecolor="tab:brown")

    # QoS Symbole für Legende
    qos0 = Line2D([], [], marker="o", color="white", markeredgecolor="tab:blue", linestyle="None")
    qos1 = Line2D([], [], marker="o", color="black", markeredgecolor="tab:blue", linestyle="None")
    qos0_sq = Line2D([], [], marker="s", color="white", markeredgecolor="tab:green", linestyle="None")
    qos1_sq = Line2D([], [], marker="s", color="black", markeredgecolor="tab:green", linestyle="None")

    max_line = Line2D([], [], color="tab:blue", linestyle="-", marker="o", label="Max Jitter")
    avg_line = Line2D([], [], color="tab:green", linestyle="--", marker="s", label="Avg Jitter")

    legend_handles = [max_line, avg_line, line_mean_y_max, line_mean_y_avg]
    if data_z:
        mean_z_max = np.mean(diffs_max_z) if diffs_max_z else 0
        mean_z_avg = np.mean(diffs_avg_z) if diffs_avg_z else 0
        line_mean_z_max = ax.axhline(mean_z_max, color="purple", linestyle="-.", linewidth=2, label="Mean Max Z")
        line_mean_z_avg = ax.axhline(mean_z_avg, color="brown", linestyle="-.", linewidth=2, label="Mean Avg Z")
        legend_handles.extend([line_mean_z_max, line_mean_z_avg])

    qos0_tuple = (qos0, qos0_sq)
    qos1_tuple = (qos1, qos1_sq)
    legend_handles.extend([qos0_tuple, qos1_tuple])

    ax.legend(
        handles=legend_handles,
        labels=["Max Jitter", "Avg Jitter", "Mean Max", "Mean Avg"]
               + (["Mean Max Z", "Mean Avg Z"] if data_z else [])
               + ["QoS=0", "QoS=1"],
        handler_map={tuple: HandlerTuple(ndivide=None)},
        loc="best"
    )

    ax.axhline(0, color="black", linestyle=":", linewidth=1)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=90)
    ax.set_xlabel("Testcase configurations (std-freq-bw-qos-proto)")
    ax.set_ylabel("Difference of jitter to baseline (%)")
    ax.set_title(f"Jitter comparison for {proto.upper()} cases")

    ax.grid(True, linestyle=":", linewidth=0.7)
    plt.tight_layout()
    plt.savefig(f"jitter_comparison_{config_x}_{config_y}_{config_z if config_z else ''}_{proto}.pdf")
    plt.close()

# -------------------------
# Zwei Plots erzeugen: UDP und TCP
# -------------------------
make_plot("udp")
make_plot("tcp")
