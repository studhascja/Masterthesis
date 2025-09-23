import os
import numpy as np

for i in range(3):
    config = str(i + 1)
    BASE_DIR = config + "/results"

    max_jitter_vals = []
    avg_jitter_vals = []
    max_latency_vals = []
    avg_latency_vals = []

    for root, dirs, files in os.walk(BASE_DIR):
        for file in files:
            if file == "latencys_0":
                path = os.path.join(root, file)

                # Rohdaten einlesen
                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])  # letzter Wert = RTT in ns
                        except ValueError:
                            continue

                if len(rtts) > 1:
                    # --- Latenzen ---
                    max_latency = max(rtts) / 1e6       # ns → ms
                    avg_latency = np.mean(rtts) / 1e6   # ns → ms
                    max_latency_vals.append(max_latency)
                    avg_latency_vals.append(avg_latency)

                    # --- Jitter ---
                    diffs = [abs(rtts[i] - rtts[i - 1]) / 1e3 for i in range(1, len(rtts))]  # ns → µs
                    if diffs:
                        max_jitter = max(rtts) - min(rtts)
                        max_jitter_vals.append(max_jitter / 1e3)  # ns → µs
                        avg_jitter_vals.append(np.mean(diffs))   # µs

    # Ergebnisse für den Testdurchgang ausgeben
    print(f"\n--- Ergebnisse für Config {config} ---")
    if max_jitter_vals:
        print(f"Maximaler Jitter:     {np.mean(max_jitter_vals):.2f} µs")
        print(f"Durchschnittlicher Jitter: {np.mean(avg_jitter_vals):.2f} µs")
        print(f"Maximale Latenz:      {np.mean(max_latency_vals):.2f} ms")
        print(f"Durchschnittliche Latenz: {np.mean(avg_latency_vals):.2f} ms")
    else:
        print("Keine gültigen Daten gefunden.")
