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
parser.add_argument("--protocol", action="store_true", help="Nach Protocol gruppieren (tcp/udp)")
args = parser.parse_args()

configs = args.config if args.config else [1, 2, 3]

# Welche Parameter sollen gruppiert werden
group_params = []
if args.standard: group_params.append("standard")
if args.frequency: group_params.append("frequency")
if args.bandwidth: group_params.append("bandwidth")
if args.qos: group_params.append("qos")
if args.protocol: group_params.append("protocol")

def calc_phase_metrics(rows):
    """
    Berechnet für Phase 0–5 und Gesamtzeit (letzte Spalte):
    - max und avg Latenz
    - max und avg Jitter
    """
    arr = np.array(rows)
    metrics = {}

    # Phasen 0–5
    phases = arr[:, :6]
    phase_avg = np.mean(phases, axis=0)
    phase_max = np.max(phases, axis=0)

    # Jitter pro Phase: Differenzen innerhalb der Phase über alle Durchgänge
    phase_jitter = np.abs(np.diff(phases, axis=0))
    phase_jitter_avg = np.mean(phase_jitter, axis=0) if phase_jitter.size > 0 else np.zeros(6)
    phase_jitter_max = np.max(phase_jitter, axis=0) if phase_jitter.size > 0 else np.zeros(6)

    metrics['phase_avg_latency'] = phase_avg
    metrics['phase_max_latency'] = phase_max
    metrics['phase_avg_jitter'] = phase_jitter_avg
    metrics['phase_max_jitter'] = phase_jitter_max

    # Gesamtzeit (letzte Spalte)
    total = arr[:, 6]
    metrics['total_avg_latency'] = np.mean(total)
    metrics['total_max_latency'] = np.max(total)

    total_jitter = np.abs(np.diff(total))
    metrics['total_avg_jitter'] = np.mean(total_jitter) if total_jitter.size > 0 else 0
    metrics['total_max_jitter'] = np.max(total_jitter) if total_jitter.size > 0 else 0

    return metrics

for config in configs:
    BASE_DIR = f"{config}/results"

    # Gruppierte Ergebnisse: key = tuple der Filterwerte, value = Liste von Zeilen
    grouped = defaultdict(list)

    for root, dirs, files in os.walk(BASE_DIR):
        if "latencys_0" in files:
            # Parameter aus Pfad extrahieren
            parts = root.split(os.sep)
            params = {
                "standard": next((p for p in parts if p.startswith("standard_")), None),
                "frequency": next((p for p in parts if p.startswith("frequency_")), None),
                "bandwidth": next((p for p in parts if p.startswith("bandwith_")), None),
                "qos": next((p for p in parts if p.startswith("qos_")), None),
                "protocol": parts[-2] if parts[-2] in ("tcp", "udp") else None,
            }

            # Gruppen-Key zusammenstellen
            key = tuple(params[param] for param in group_params)

            # Datei einlesen
            path = os.path.join(root, "latencys_0")
            rows = []
            with open(path, "r") as f:
                for line in f:
                    try:
                        numbers = list(map(int, map(float, line.strip().split(","))))
                        if len(numbers) == 7:
                            rows.append(numbers)
                    except ValueError:
                        continue

            if rows:
                grouped[key].extend(rows)

    print(f"\n--- Ergebnisse für Config {config} ---")
    if grouped:
        if not group_params:
            # Ohne Gruppierung: alles aggregieren
            all_rows = [row for rows in grouped.values() for row in rows]
            metrics = calc_phase_metrics(all_rows)

            for i in range(6):
                print(f"Phase {i+1}: Avg Latenz={metrics['phase_avg_latency'][i]:.2f} ms, "
                      f"Max Latenz={metrics['phase_max_latency'][i]:.2f} ms, "
                      f"Avg Jitter={metrics['phase_avg_jitter'][i]:.2f} µs, "
                      f"Max Jitter={metrics['phase_max_jitter'][i]:.2f} µs")

            print(f"Gesamtzeit: Avg Latenz={metrics['total_avg_latency']:.2f} ms, "
                  f"Max Latenz={metrics['total_max_latency']:.2f} ms, "
                  f"Avg Jitter={metrics['total_avg_jitter']:.2f} µs, "
                  f"Max Jitter={metrics['total_max_jitter']:.2f} µs")

        else:
            # Mit Gruppierung
            for key, rows in grouped.items():
                metrics = calc_phase_metrics(rows)
                label = ", ".join([k for k in key if k is not None])
                print(f"\n{label}:")
                for i in range(6):
                    print(f"  Phase {i+1}: Avg Latenz={metrics['phase_avg_latency'][i]:.2f} ms, "
                          f"Max Latenz={metrics['phase_max_latency'][i]:.2f} ms, "
                          f"Avg Jitter={metrics['phase_avg_jitter'][i]:.2f} µs, "
                          f"Max Jitter={metrics['phase_max_jitter'][i]:.2f} µs")

                print(f"  Gesamtzeit: Avg Latenz={metrics['total_avg_latency']:.2f} ms, "
                      f"Max Latenz={metrics['total_max_latency']:.2f} ms, "
                      f"Avg Jitter={metrics['total_avg_jitter']:.2f} µs, "
                      f"Max Jitter={metrics['total_max_jitter']:.2f} µs")
    else:
        print("Keine gültigen Daten gefunden.")
