import os
import numpy as np
import matplotlib.pyplot as plt

BASE_DIR = "3/results"

phase_shares = {}

# --- Daten sammeln ---
for root, dirs, files in os.walk(BASE_DIR):
    for file in files:
        if file == "latencys_0":
            path = os.path.join(root, file)

            with open(path, "r") as f:
                for line in f:
                    try:
                        numbers = list(map(int, line.strip().split(",")))
                        if len(numbers) < 2:
                            continue

                        phases = numbers[:-1]  # 6 Phasen
                        sum_phases = sum(phases)
                        if sum_phases <= 0:
                            continue
                        if all(p > 0 for p in phases):
                        # Normalisiere auf 100 %
                            shares = [p / sum_phases * 100 for p in phases]

                            for i, share in enumerate(shares):
                                phase_shares.setdefault(i, []).append(share)

                    except ValueError:
                        continue

# --- Minimum und Maximum pro Phase ---
phase_minmax = {}
for phase, shares in phase_shares.items():
    phase_minmax[phase] = (min(shares), max(shares))

print("Phase\tMin (%)\tMax (%)")
for phase, (minv, maxv) in phase_minmax.items():
    print(f"{phase+1}\t{minv:.2f}\t{maxv:.2f}")

# --- Durchschnitt pro Phase ---
phase_avg = {}
for phase, shares in phase_shares.items():
    phase_avg[phase] = np.mean(shares)

# Werte für Plot
avg_values = [phase_avg[p] for p in sorted(phase_avg.keys())]
labels = [f"Phase {p+1}" for p in sorted(phase_avg.keys())]

# --- Donut-Diagramm für Durchschnitt ---
fig, ax = plt.subplots(figsize=(8, 8))
wedges, texts, autotexts = ax.pie(
    avg_values, radius=1, labels=labels, labeldistance=1.05,
    autopct="%1.1f%%", pctdistance=0.85, startangle=90
)

# Donut-Loch
centre_circle = plt.Circle((0, 0), 0.4, fc="white")
ax.add_artist(centre_circle)

ax.set_title("Durchschnittliche Anteile pro Phase")
plt.tight_layout()
plt.savefig("phase_shares_avg.png", dpi=300)
plt.close()
print("Fertig! Durchschnitts-Donut gespeichert in phase_shares_avg.png")
