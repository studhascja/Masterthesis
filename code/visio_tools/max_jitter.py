import os
import numpy as np
import matplotlib.pyplot as plt

# --- Alle Runs zusammen sammeln ---
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
                proto = parts[6]

                test_key = f"{std}-{freq}-{bw}"  # nur ohne QoS/Proto
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

# --- Jitter-Kennzahlen berechnen ---
jitter_stats = {}  # (test_key, proto, qos) -> {"max": val, "avg": val}

for (test_key, proto, qos), runs in all_latency_data.items():
    max_vals = []
    avg_vals = []
    for rtts in runs:
        # optional: Ausreißer filtern
        rtts = [val for val in rtts if val < 1e8]  # Werte < 100 ms
        if len(rtts) < 2:
            continue
        jitter_val = (max(rtts) - min(rtts)) / 1e3  # ns → µs
        diffs = [abs(rtts[i] - rtts[i - 1]) / 1e3 for i in range(1, len(rtts))]
        avg_val = np.mean(diffs) if diffs else np.nan
        max_vals.append(jitter_val)
        avg_vals.append(avg_val)

    if max_vals and avg_vals:
        jitter_stats[(test_key, proto, qos)] = {
            "max": np.nanmax(max_vals),
            "avg": np.nanmean(avg_vals)
        }

# --- X-Achse vorbereiten ---
x_labels = sorted({k[0] for k in jitter_stats.keys()})
x = np.arange(len(x_labels))

def get_curve(proto, qos, mode):
    return [jitter_stats.get((lbl, proto, qos), {}).get(mode, np.nan) for lbl in x_labels]

# --- Farben und Marker ---
colors = {
    ("udp", "1"): "darkgreen",
    ("udp", "0"): "green",
    ("tcp", "1"): "darkblue",
    ("tcp", "0"): "blue",
}
markers = {"1": "x", "0": "o"}

# --- Grafik für Maximal-Jitter ---
plt.figure(figsize=(14, 7))
for proto in ["udp", "tcp"]:
    for qos in ["1", "0"]:
        plt.plot(
            x,
            get_curve(proto, qos, "max"),
            marker=markers[qos],
            color=colors[(proto, qos)],
            label=f"{proto.upper()} {'mit' if qos=='1' else 'ohne'} QoS – max",
        )
plt.xticks(x, x_labels, rotation=45, ha="right")
plt.ylabel("Maximaler Jitter (µs)")
plt.title("Maximaler Jitter über alle 3 Runs")
plt.legend(ncol=2, fontsize=9)
plt.tight_layout()
plt.savefig("jitter_max_all.png")
plt.savefig("jitter_max_all.pgf")
plt.close()

# --- Grafik für Durchschnitts-Jitter ---
plt.figure(figsize=(14, 7))
for proto in ["udp", "tcp"]:
    for qos in ["1", "0"]:
        plt.plot(
            x,
            get_curve(proto, qos, "avg"),
            marker=markers[qos],
            color=colors[(proto, qos)],
            label=f"{proto.upper()} {'mit' if qos=='1' else 'ohne'} QoS – avg",
        )
plt.xticks(x, x_labels, rotation=45, ha="right")
plt.ylabel("Durchschnittlicher Jitter (µs)")
plt.title("Durchschnittlicher Jitter über alle 3 Runs")
plt.legend(ncol=2, fontsize=9)
plt.tight_layout()
plt.savefig("jitter_avg_all.png")
plt.savefig("jitter_avg_all.pgf")
plt.close()

print("Fertig! Max- und Avg-Jitter wurden in getrennten Grafiken erstellt.")
