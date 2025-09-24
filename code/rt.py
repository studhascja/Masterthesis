import os
import numpy as np
import matplotlib.pyplot as plt
import itertools

# Farbpalette für die Kombinationen
from matplotlib.cm import get_cmap
cmap = get_cmap("tab20")  # 20 verschiedene Farben

# Dictionary für zusammengelegte Daten
combined_test_data = {"tcp": {}, "udp": {}}

# --- Daten sammeln ---
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

                # Test-ID enthält alle relevanten Infos
                test_id = f"{proto}-std{std}-f{freq}-bw{bw}-qos{qos}"

                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])
                        except ValueError:
                            continue

                if rtts:
                    latencies_ms = np.array(rtts) / 1e6
                    if test_id in combined_test_data[proto]:
                        combined_test_data[proto][test_id] = np.concatenate(
                            [combined_test_data[proto][test_id], latencies_ms]
                        )
                    else:
                        combined_test_data[proto][test_id] = latencies_ms


def plot_variant(proto, qos_value):
    """Erstellt CDFs für eine Variante (tcp/udp + qos), jede Kombination mit eigener Farbe."""
    # Filtere Daten nach QoS
    data = {k: v for k, v in combined_test_data[proto].items() if k.endswith(f"qos{qos_value}")}
    if not data:
        return

    # Erstelle Farbliste für alle Kombinationen
    all_combinations = list(data.keys())
    n_colors = len(all_combinations)
    colors = [cmap(i % 20) for i in range(n_colors)]

    fig, axes = plt.subplots(3, 2, sharey="row", figsize=(14, 10),
                             gridspec_kw={"hspace": 0, "wspace": 0})
    axes = np.array(axes)

    y_ranges = [
        (99.9, 100, [99.93, 99.96, 99.99, 100]),
        (99, 99.9, [99.3, 99.6, 99.9]),
        (95, 99, [95, 96, 97, 98, 99])
    ]
    x_ranges = [(1, 5, [1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5]),
                (5, 15, [7.5, 10.0, 12.5, 15.0])]

    for i, (test_id, latencies_ms) in enumerate(data.items()):
        color = colors[i]
        latencies_ms = np.sort(latencies_ms)
        n = len(latencies_ms)
        y = np.arange(1, n + 1) / n * 100
        label = test_id  # Test-ID als Label

        for row, (ymin, ymax, yticks) in enumerate(y_ranges):
            for col, (xmin, xmax, xticks) in enumerate(x_ranges):
                ax = axes[row, col]
                marker_count = {0: 1500, 1: 200, 2: 50}.get(row, 1000)
                ax.plot(latencies_ms, y,
                        label=label,
                        linewidth=2.5,
                        color=color,
                        linestyle='-',
                        marker=None,
                        markevery=max(1, len(latencies_ms)//marker_count))
                ax.set_xlim(xmin, xmax)
                ax.set_ylim(ymin, ymax)
                ax.set_yticks(yticks)
                ax.set_xticks(xticks)

    fig.supxlabel("Latenz (ms)")
    axes[1, 0].set_ylabel("Kumulative Wahrscheinlichkeit (%)")
    axes[0, 0].set_title(f"CDF der Latenzen – {proto.upper()} QoS={qos_value}", fontsize=14, loc="left")

    for row in range(2):
        for col in range(2):
            axes[row, col].xaxis.set_visible(False)
            axes[row, col].spines['bottom'].set_visible(False)
            axes[row + 1, col].spines['top'].set_color("grey")
            axes[row + 1, col].spines['top'].set_linestyle(":")
            axes[row + 1, col].spines['top'].set_linewidth(2)

    for row in range(3):
        ax_left, ax_right = axes[row]
        ax_left.spines['right'].set_visible(False)
        ax_right.spines['left'].set_visible(False)
        ax_right.yaxis.set_visible(False)

    plt.legend(loc="lower right", ncol=2, fontsize=8)
    plt.tight_layout(rect=[0, 0.05, 1, 1])
    plt.savefig(f"latency_cdf_{proto}_qos{qos_value}.png", dpi=300)
    plt.close()
    print(f"Fertig! CDF-Diagramm für {proto.upper()} QoS={qos_value} gespeichert.")


# Vier Varianten erstellen: tcp/udp × qos 0/1
for proto in ["tcp", "udp"]:
    for qos in ["0", "1"]:
        plot_variant(proto, qos)
