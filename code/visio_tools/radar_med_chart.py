import os
import numpy as np
import matplotlib.pyplot as plt
import math

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
                    data[key] = np.mean(rtts)
    return data

latency_data = load_latency_data(BASE_DIR)

# -------------------------
# Faktoren & Indices
# -------------------------
factors = ["Standard", "Frequency", "Bandwidth", "QoS", "Protocol"]
factor_indices = {"Standard": 0, "Frequency": 1, "Bandwidth": 2, "QoS": 3, "Protocol": 4}

r_values = []
theta_values = []

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

all_values = [val for factor_dict in results.values() for val in factor_dict.values()]

# Höchster Wert
max_value = math.ceil(max(all_values)/10)*10
# -------------------------
# Radial Bar Chart
# -------------------------
fig, ax = plt.subplots(figsize=(12, 12), subplot_kw=dict(polar=True))

N = len(factors)
angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
sector_width = 2*np.pi / N

# Farben für die Sektoren (Pastellfarben)
sector_colors = ["yellow", "#3944BC", "orange", "#A3E77F", "turquoise"]


# feste Balkenbreite
bar_width = sector_width * 0.2  # 20% der Sektorbreite
ax.set_xticks([a + sector_width/2 for a in angles])
ax.tick_params(axis='x', labelbottom=False) 
ax.set_xticklabels([])
ax.set_yticklabels([])
ax.tick_params(axis='y', labelbottom=False) 

ax.yaxis.grid(False)
ax.xaxis.grid(False)
ax.spines['polar'].set_visible(False)

thetas = np.linspace(0, 2*np.pi, 200)  # feine Auflösung

for r in np.arange(10, max_value + 10, 10):  # gewünschte Grid-Radien
    ax.plot(thetas, np.full_like(thetas, r), color="grey", linewidth=1, linestyle="--")

theta_label = np.radians(-10)
for y in np.arange(0, max_value, 20):
    ax.text(theta_label, y, str(int(y)), ha='center', va='center', fontsize=10, fontweight="bold")

for i, factor in enumerate(factors):
    values = results[factor]
    levels = sorted(values.keys())
    n_levels = len(levels)
    sector_lenght = 0
    level_count = 0

    for lvl in levels:
        sector_lenght += abs(values[lvl])
        level_count += 1

    sector_lenght = sector_lenght / level_count if level_count > 0 else 0
    r_values.append(sector_lenght)
    theta_values.append(angles[i] + sector_width/2)
    # Startwinkel für das Zentrum des Faktors
    base_angle = angles[i] + sector_width/2

    ax.bar(
        angles[i],                     # Startwinkel (0 Radiant = rechts)
        height=15,                 # Radius-Höhe
        width=sector_width,             # voller Kreis
        bottom=max_value + 20,                   # von Zentrum aus
        facecolor=(sector_colors[i]),
          # Transparenz
        edgecolor="black",
        linewidth=2.5,
        align="edge"
    )

    r_text = max_value + 22 + 10/2  # bottom + height/2
    theta_text = angles[i] + sector_width/2

# Drehung berechnen
    rotation = np.degrees(theta_text) - 90

    ax.text(
        theta_text, r_text,
        factor,
        ha="center", va="center",          # immer zentriert
        rotation=rotation,
        rotation_mode="anchor",
        fontsize=12, fontweight="bold"
    )

    ax.bar(
        angles[i], 
        max_value + 10,  
        width=sector_width, 
        bottom=0, 
        facecolor=(sector_colors[i], 0.1),
        align="edge",
        edgecolor="black",
        linewidth=2.5
    )

    ax.bar(
        angles[i], 
        sector_lenght,  
        width=sector_width, 
        color=sector_colors[i],
        bottom=0, 
        alpha=0.5,
        align="edge"
    )
    for j, lvl in enumerate(levels):
        val = values[lvl]

        # gleichmäßig innerhalb des Faktors verteilen
        offset = (j - (n_levels-1)/2) * (bar_width * 1.2)  
        ax.bar(
            base_angle + offset, 
            max_value + 10,
            facecolor=(sector_colors[i], 0.1), 
            width=bar_width, bottom=0,
            edgecolor="black", linewidth=2
        )

        ax.bar(
            base_angle + offset, 
            20,
            facecolor=("grey", 0.3), 
            width=bar_width, bottom=max_value,
            edgecolor="black", linewidth=2
        )

        ax.bar(
            base_angle + offset, abs(val),
            width=bar_width, bottom=0,
            color="green" if val < 0 else "red", alpha=0.7
        )
        rmax = ax.get_ylim()[1]  # maximaler Radius

        r_text = max_value + 10 + 10/2  # bottom + height/2
        theta_text = base_angle + offset


        rotation = np.degrees(theta_text) - 90

        ax.text(
            theta_text, r_text,
             f"{lvl}",
            ha="center", va="center",          # immer zentriert
            rotation=rotation,
            rotation_mode="anchor",
            fontsize=12, fontweight="bold"
        )

        ax.text(
            theta_text, r_text - 12,
             f"{val:.1f}",
            ha="center", va="center",          # immer zentriert
            rotation=rotation,
            rotation_mode="anchor",
            fontsize=12, fontweight="bold"
        )
        
r_values.append(r_values[0])
theta_values.append(theta_values[0])
ax.plot(theta_values, r_values, color="black", linewidth=2, linestyle="-", marker="o")
ax.fill(theta_values, r_values, color="gray", alpha=0.8)


plt.show()
