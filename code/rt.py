import os
import numpy as np
import matplotlib.pyplot as plt
import itertools

# Verschiedene Linienstile, damit man die Kurven besser unterscheiden kann
line_styles = ["-", "--", "-.", ":"]
colors = plt.cm.tab20.colors  # 20 verschiedene Farben

for i in range(3):
    config = str(i + 1)
    BASE_DIR = config + "/results"

    test_data = {}

    # --- Rohdaten einlesen ---
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
                test_name = f"{std}-{freq}-{bw}-{qos}-{proto}"

                rtts = []
                with open(path, "r") as f:
                    for line in f:
                        try:
                            numbers = list(map(int, line.strip().split(",")))
                            rtts.append(numbers[-1])  # RTT in ns
                        except ValueError:
                            continue

                if rtts:
                    # ns → ms
                    latencies_ms = np.array(rtts) / 1e6
                    test_data[test_name] = np.sort(latencies_ms)

    # --- Plot erstellen ---
    plt.figure(figsize=(12, 8))
    fig, ax = plt.subplots(layout='constrained')

    ax.set_yscale('function', functions=(forward, inverse))
    ax.set_title('function: Mercator')
    ax.grid(True)
    # Generator für Farben und Linienstile
    style_cycle = itertools.cycle([(c, ls) for c in colors for ls in line_styles])

    for test_name, latencies_ms in test_data.items():
        n = len(latencies_ms)
        y = np.arange(1, n + 1) / n * 100  # Prozentwerte

        color, linestyle = next(style_cycle)
        plt.plot(
            latencies_ms,
            y,
            label=test_name,
            linewidth=1.2,
            color=color,
            linestyle=linestyle,
        )

    # Achsenformatierung
    plt.xlabel("Latenz (ms)")
    plt.ylabel("Kumulative Wahrscheinlichkeit (%)")
    plt.title(f"CDF der Latenzen – Config {config}")
    plt.xlim(0, 20)
    # Bereich von 50–100 %
    plt.ylim(50, 100)

    # feines Raster zwischen 99–100 %
    plt.yticks(
        list(range(50, 100, 5)) + [99, 99.9, 99.99, 99.999, 100]
    )
    
    plt.set_yscale('function', functions=(forward, inverse))
    plt.grid(True, which="both", linestyle="--", linewidth=0.5, alpha=0.7)

    plt.legend(fontsize=7, loc="lower right", ncol=2)
    plt.tight_layout()
    plt.savefig(f"latency_cdf_config_{config}.png", dpi=300)
    plt.close()

    print(f"Fertig! CDF-Diagramm für Config {config} gespeichert.")
