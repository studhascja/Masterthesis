import os
import numpy as np
import matplotlib.pyplot as plt

# -------------------------
# Config auswählen
# -------------------------
config = input("Welche Config soll geplottet werden? (z.B. 1): ").strip()
BASE_DIR = config + "/results"

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

latency_data = load_latency_data(BASE_DIR)

# -------------------------
# Faktoren & Indices
# -------------------------
factors = ["Standard", "Frequenz", "Bandbreite", "QoS", "Protokoll"]
factor_indices = {"Standard": 0, "Frequenz": 1, "Bandbreite": 2, "QoS": 3, "Protokoll": 4}

# -------------------------
# Prozentuale Unterschiede berechnen
# -------------------------
def percent_diffs_for_factor(data, factor_index):
    """Berechne die mittleren % Unterschiede für jede Stufe eines Faktors."""
    diffs_per_level = {}
    keys = list(data.keys())

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            k1, k2 = keys[i], keys[j]

            # nur vergleichen, wenn sich genau dieser Faktor unterscheidet
            if all((a == b) if idx != factor_index else (a != b)
                   for idx, (a, b) in enumerate(zip(k1, k2))):
                v1, v2 = data[k1], data[k2]
                if (v1 + v2) > 0:
                    diff = abs(v1 - v2) / ((v1 + v2) / 2) * 100
                    # Schlechtere Stufe +
                    if v1 > v2:
                        diffs_per_level.setdefault(k1[factor_index], []).append(+diff)
                        diffs_per_level.setdefault(k2[factor_index], []).append(-diff)
                    else:
                        diffs_per_level.setdefault(k2[factor_index], []).append(+diff)
                        diffs_per_level.setdefault(k1[factor_index], []).append(-diff)

    # Mittelwerte pro Stufe
    return {lvl: np.mean(vals) for lvl, vals in diffs_per_level.items()}

results = {f: percent_diffs_for_factor(latency_data, factor_indices[f]) for f in factors}

# -------------------------
# Radial Bar Chart
# -------------------------
fig, ax = plt.subplots(figsize=(12, 12), subplot_kw=dict(polar=True))

N = len(factors)
angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
sector_width = 2*np.pi / N

# Farben für die Sektoren (Pastellfarben)
sector_colors = ["red", "blue", "orange", "yellow", "turquoise"]

# feste Balkenbreite
bar_width = sector_width * 0.2  # 20% der Sektorbreite

for i, factor in enumerate(factors):
    values = results[factor]
    levels = sorted(values.keys())
    n_levels = len(levels)

    # Startwinkel für das Zentrum des Faktors
    base_angle = angles[i] + sector_width/2
    ax.bar(
        angles[i], 
        100,  
        width=sector_width, 
        bottom=0, 
        color=sector_colors[i-1], 
        alpha=0.3,
        align="edge"
    )
    for j, lvl in enumerate(levels):
        val = values[lvl]

        # gleichmäßig innerhalb des Faktors verteilen
        offset = (j - (n_levels-1)/2) * (bar_width * 1.2)  
        ax.bar(
            base_angle + offset, 
            100,
            width=bar_width, bottom=0,
            color="green" if val < 0 else "red", alpha=0.2
        )
        ax.bar(
            base_angle + offset, abs(val),
            width=bar_width, bottom=0,
            color="green" if val < 0 else "red", alpha=0.7
        )
        rmax = ax.get_ylim()[1]  # maximaler Radius
        ax.text(
            base_angle + offset, rmax + 5,   # alle außen hin
            f"{lvl}\n{val:.1f}%",
            ha="center", va="center", fontsize=10, fontweight="bold"
        )

        #ax.text(
         #   base_angle + offset, abs(val) + 12,
          #  f"{lvl}\n{val:.1f}%",
           # ha="center", va="center", fontsize=10, fontweight="bold"
        #)

ax.set_xticks([a + sector_width/2 for a in angles])
ax.set_xticklabels(factors, fontsize=12, fontweight="bold")
ax.set_yticklabels([])
ax.set_title(f"Einflussfaktoren (Config {config}) – Durchschnittliche % Differenzen", va="bottom", fontsize=14)

plt.show()
