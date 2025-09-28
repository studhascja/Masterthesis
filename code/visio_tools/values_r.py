import os
import numpy as np
import argparse
from collections import defaultdict

parser = argparse.ArgumentParser(description="Analyse von Latenz- und Jitterdaten")
parser.add_argument("--config", type=int, nargs="*", help="Welche Configs auswerten (1,2,3). Standard: alle")
parser.add_argument("--standard", action="store_true", help="Nach Standard gruppieren")
parser.add_argument("--frequency", action="store_true", help="Nach Frequency gruppieren")
parser.add_argument("--bandwidth", action="store_true", help="Nach Bandwidth gruppieren")
parser.add_argument("--qos", action="store_true", help="Nach QOS gruppieren")
parser.add_argument("--protocol", action="store_true", help="Nach Protocol gruppieren")
args = parser.parse_args()

configs = args.config if args.config else [1, 2, 3]

# Welche Parameter sollen gruppiert werden
group_params = []
if args.standard: group_params.append("standard")
if args.frequency: group_params.append("frequency")
if args.bandwidth: group_params.append("bandwith")
if args.qos: group_params.append("qos")
if args.protocol: group_params.append("protocol")

for config in configs:
    BASE_DIR = f"{config}/results"

    # Gruppierte Ergebnisse: key = tuple der Filterwerte, value = Liste von Messwerten
    grouped = defaultdict(list)

    for root, dirs, files in os.walk(BASE_DIR):
        if "latencys_0" in files:
            # Werte für Gruppen-Key extrahieren
            key = []
            for param in group_params:
                # Suche nach Parameter im Pfad
                matches = [d for d in root.split(os.sep) if param in d]
                key.append(matches[0] if matches else None)
            key = tuple(key)

            # Messwerte einlesen
            path = os.path.join(root, "latencys_0")
            rtts = []
            with open(path, "r") as f:
                for line in f:
                    try:
                        numbers = list(map(int, line.strip().split(",")))
                        rtts.append(numbers[-1])
                    except ValueError:
                        continue

            if len(rtts) > 1:
                max_latency = max(rtts) / 1e6
                avg_latency = np.mean(rtts) / 1e6
                diffs = [abs(rtts[i] - rtts[i-1])/1e3 for i in range(1,len(rtts))]
                max_jitter = (max(rtts)-min(rtts))/1e3
                avg_jitter = np.mean(diffs) if diffs else 0

                grouped[key].append({
                    "max_latency": max_latency,
                    "avg_latency": avg_latency,
                    "max_jitter": max_jitter,
                    "avg_jitter": avg_jitter
                })

    print(f"\n--- Ergebnisse für Config {config} ---")
    if grouped:
        # Wenn keine Gruppen gewählt, Mittelwert über alle
        if not group_params:
            all_max_latency = [v["max_latency"] for values in grouped.values() for v in values]
            all_avg_latency = [v["avg_latency"] for values in grouped.values() for v in values]
            all_max_jitter = [v["max_jitter"] for values in grouped.values() for v in values]
            all_avg_jitter = [v["avg_jitter"] for values in grouped.values() for v in values]

            print(f"Maximaler Jitter:     {np.max(all_max_jitter):.2f} µs")
            print(f"Durchschnittlicher Jitter: {np.mean(all_avg_jitter):.2f} µs")
            print(f"Maximale Latenz:      {np.max(all_max_latency):.2f} ms")
            print(f"Durchschnittliche Latenz: {np.mean(all_avg_latency):.2f} ms")
        else:
            # Für jede Gruppe Mittelwerte ausgeben
            for key, values in grouped.items():
                label = ", ".join([k for k in key if k is not None])
                max_latency = np.max([v["max_latency"] for v in values])
                avg_latency = np.mean([v["avg_latency"] for v in values])
                max_jitter = np.max([v["max_jitter"] for v in values])
                avg_jitter = np.mean([v["avg_jitter"] for v in values])
                print(f"{label}: Max Latenz={max_latency:.2f} ms, Avg Latenz={avg_latency:.2f} ms, Max Jitter={max_jitter:.2f} µs, Avg Jitter={avg_jitter:.2f} µs")
    else:
        print("Keine gültigen Daten gefunden.")
