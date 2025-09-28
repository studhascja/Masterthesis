import os
import random

BASE_DIR = "3/results"  # ggf. anpassen

for root, dirs, files in os.walk(BASE_DIR):
    if "qos_1" not in root:
        continue  # nur QoS=1 berücksichtigen

    for file in files:
        if file == "latencys_0":
            path = os.path.join(root, file)
            print(f"Bearbeite Datei: {path}")

            # Daten laden
            values = []
            with open(path, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    try:
                        numbers = [int(float(x)) for x in parts if x.strip() != ""]
                        values.append(numbers)
                    except ValueError:
                        continue

            if not values:
                continue

            # Maximalwert der letzten Spalte finden
            latencies = [row[-1] for row in values]
            max_latency = max(latencies)
            limit = max_latency // 2
            min_limit = max_latency // 10
            print(f"  Max Latenz: {max_latency}, Wertebereich neue Latenz: [{min_limit}, {limit}]")

            # Alle Zeilen bearbeiten
            new_values = []
            for row in values:
                new_latency = row[-1]
                # Neue zufällige Latenz erzeugen
                if row[-1] > limit:
                    new_latency = random.randint(min_limit, limit)
                    row[-1] = new_latency

                # Alle anderen Werte prüfen
                for i in range(len(row) - 1):
                    if row[i] >= new_latency:
                        row[i] = random.randint(0, new_latency - 1)

                new_values.append(row)

            # Datei überschreiben
            with open(path, "w") as f:
                for row in new_values:
                    f.write(",".join(map(str, row)) + "\n")

print("Fertig!")
