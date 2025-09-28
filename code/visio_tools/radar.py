import os
import numpy as np
import matplotlib.pyplot as plt

# -------------------------
# Config auswählen
# -------------------------
config = input("Welche Config soll geplottet werden? (z.B. 1, 2, 3): ").strip()
BASE_DIR = config + "/results"

# Dict: (standard, freq, bw, qos, proto) -> Mittelwert-Latenz
latency_data = {}

for root, dirs, files in os.walk(BASE_DIR):
    for file in files:
        if file == "latencys_0":
            path = os.path.join(root, file)
            parts = path.split(os.sep)
            # Erwartet: results/standard_X/frequency_Y/bandwith_Z/qos_W/{tcp,udp}/latencys_0
            std = parts[2].split("_")[1]
            freq = parts[3].split("_")[1]
            bw = parts[4].split("_")[1]
            qos = parts[5].split("_")[1]
            proto = parts[6]

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
                latency_data[key] = np.mean(rtts)


# -------------------------
# Differenzen berechnen
# -------------------------
def mean_diff_for_factor(data, factor_index, factor_name):
    """
    Berechne den Mittelwert der Differenzen für einen bestimmten Faktor.
    Gibt auch die Pfade aus, die berücksichtigt wurden.
    """
    diffs = []
    keys = list(data.keys())

    print(f"\n--- Faktor {factor_name} ---")

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            k1, k2 = keys[i], keys[j]

            # Prüfen, ob sich nur der gewünschte Faktor unterscheidet
            if all(
                (a == b) if idx != factor_index else (a != b)
                for idx, (a, b) in enumerate(zip(k1, k2))
            ):
                diff = abs(data[k1] - data[k2])
                diffs.append(diff)
                print(f"{k1} vs {k2} -> Δ {diff:.2f}")

    return np.mean(diffs) if diffs else 0


# Faktoren in der Reihenfolge
factors = ["Standard", "Frequenz", "Bandbreite", "QoS", "Protokoll"]

# Index-Zuordnung (wie in den Keys gespeichert)
# key = (std, freq, bw, qos, proto)
factor_indices = {
    "Standard": 0,
    "Frequenz": 1,
    "Bandbreite": 2,
    "QoS": 3,
    "Protokoll": 4
}

# Berechnen der durchschnittlichen Differenzen
results = [
    mean_diff_for_factor(latency_data, factor_indices[f], f) for f in factors
]


# -------------------------
# Radarplot
# -------------------------
def radar_chart(labels, values, title):
    n = len(labels)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    values += values[:1]  # schließen
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    ax.plot(angles, values, "o-", linewidth=2)
    ax.fill(angles, values, alpha=0.25)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels)
    ax.set_title(title)
    plt.tight_layout()
    plt.show()


radar_chart(factors, results, f"Einflussfaktoren auf mittlere Latenz (Config {config})")

print("\nDurchschnittliche Differenzen pro Faktor:")
for f, val in zip(factors, results):
    print(f"{f}: {val:.2f}")
