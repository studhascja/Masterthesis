import os
import numpy as np
import matplotlib.pyplot as plt

# -------------------------
# Configs auswählen
# -------------------------
configs = input("Welche zwei Configs sollen verglichen werden? (z.B. 1 2): ").strip().split()
if len(configs) != 2:
    raise ValueError("Bitte genau zwei Configs angeben!")

BASE_DIRS = [c + "/results" for c in configs]

# -------------------------
# Daten laden
# -------------------------
def load_latency_data(base_dir):
    data = {}
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file == "latencys_0":
                path = os.path.join(root, file)
                parts = path.split(os.sep)
                try:
                    std = parts[2].split("_")[1]
                    freq = parts[3].split("_")[1]
                    bw = parts[4].split("_")[1]
                    qos = parts[5].split("_")[1]
                    proto = parts[6]
                except IndexError:
                    continue

                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])
                        except ValueError:
                            continue

                if rtts:
                    key = (std, freq, bw, qos, proto)
                    data[key] = np.max(rtts)
    return data

latency_data = [load_latency_data(d) for d in BASE_DIRS]

# -------------------------
# Prozentuale Unterschiede berechnen
# -------------------------
factors = ["Standard", "Frequenz", "Bandbreite", "QoS", "Protokoll"]
factor_indices = {"Standard": 0, "Frequenz": 1, "Bandbreite": 2, "QoS": 3, "Protokoll": 4}

def percent_diffs_for_factor(data, factor_index):
    diffs_per_level = {}
    keys = list(data.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            k1, k2 = keys[i], keys[j]
            if all((a == b) if idx != factor_index else (a != b)
                   for idx, (a, b) in enumerate(zip(k1, k2))):
                v1, v2 = data[k1], data[k2]
                if (v1 + v2) > 0:
                    if v1 > v2:
                        diff = -(100 - (v2 / v1 * 100))  # negativ = schlechter
                        diffs_per_level.setdefault(k1[factor_index], []).append(diff)
                        diffs_per_level.setdefault(k2[factor_index], []).append(-diff)
                    else:
                        diff = -(100 - (v1 / v2 * 100))
                        diffs_per_level.setdefault(k2[factor_index], []).append(diff)
                        diffs_per_level.setdefault(k1[factor_index], []).append(-diff)
    # Mittelwert pro Level
    return {lvl: np.mean(vals) for lvl, vals in diffs_per_level.items()}

results = {}
for f in factors:
    idx = factor_indices[f]
    results[f] = percent_diffs_for_factor(latency_data[0], idx)

# -------------------------
# Radial Bar Chart
# -------------------------
fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

N = len(factors)
angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()

bars = []
labels = []
for i, factor in enumerate(factors):
    values = results[factor]
    levels = sorted(values.keys())
    for j, lvl in enumerate(levels):
        val = values[lvl]
        angle = angles[i]
        bar = ax.bar(
            angle, abs(val), width=2*np.pi/N/len(levels), bottom=0,
            color="green" if val < 0 else "red", alpha=0.6
        )
        ax.text(angle, abs(val)+5, f"{lvl}\n{val:.1f}%", ha="center", va="center")

ax.set_xticks(angles)
ax.set_xticklabels(factors)
ax.set_yticklabels([])
ax.set_title(f"Radial Bar Chart – Vergleich Config {configs[0]} vs {configs[1]}", va="bottom")

plt.show()
