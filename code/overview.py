import os
import matplotlib.pyplot as plt
import numpy as np

def calculate_latency_statistics(latencies):
    if not latencies:
        return None

    server_do = [t[0] for t in latencies]
    server_queue = [t[1] for t in latencies]
    server_send = [t[2] for t in latencies]
    client_do = [t[3] for t in latencies]
    client_queue = [t[4] for t in latencies]
    client_send = [t[5] for t in latencies]
    cycle_times = [t[6] for t in latencies]

    avg_server_do = sum(server_do) / len(server_do) / 1_000_000
    max_server_do = max(server_do) / 1_000_000

    avg_server_queue = sum(server_queue) / len(server_queue) / 1_000_000
    max_server_queue = max(server_queue) / 1_000_000

    avg_server_send = sum(server_send) / len(server_send) / 1_000_000
    max_server_send = max(server_send) / 1_000_000

    avg_client_do = sum(client_do) / len(client_do) / 1_000_000
    max_client_do = max(client_do) / 1_000_000

    avg_client_queue = sum(client_queue) / len(client_queue) / 1_000_000
    max_client_queue = max(client_queue) / 1_000_000

    avg_client_send = sum(client_send) / len(client_send) / 1_000_000
    max_client_send = max(client_send) / 1_000_000

    avg_latency = sum(cycle_times) / len(cycle_times) / 1_000_000
    max_latency = max(cycle_times) / 1_000_000

    over_3ms_count = sum(1 for c in cycle_times if c / 1_000_000 > 3)

    return {
        'server_do': (avg_server_do, max_server_do),
        'server_queue': (avg_server_queue, max_server_queue),
        'server_send': (avg_server_send, max_server_send),
        'client_do': (avg_client_do, max_client_do),
        'client_queue': (avg_client_queue, max_client_queue),
        'client_send': (avg_client_send, max_client_send),
        'cycle_time': (avg_latency, max_latency),
        'RT-violation count': over_3ms_count
    }

def read_latencys_file(filepath):
    latencies = []
    with open(filepath, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 7:
                latencies.append(tuple(map(int, parts[:7])))
    return latencies

def collect_all_results(root_folder):
    results = []
    for dirpath, _, filenames in os.walk(root_folder):
        if "latencys_1" in filenames:
            full_path = os.path.join(dirpath, "latencys_1")
            latencies = read_latencys_file(full_path)
            stats = calculate_latency_statistics(latencies)
            if not stats:
                continue

            # Label zusammensetzen
            parts = dirpath.split(os.sep)
            try:
                standard = parts[-4].replace("standard_", "")
                frequency = parts[-3].replace("frequency_", "")
                bandwidth = parts[-2].replace("bandwith_", "")
                qos = parts[-1].replace("qos_", "")
                label = f"{standard}, {frequency}, {bandwidth}, {qos}"
                
            except IndexError:
                label = dirpath

            results.append((label, stats))
    return results

def plot_dashboard(results):
    phases = ['server_do', 'server_queue', 'server_send',
              'client_do', 'client_queue', 'client_send',
              'cycle_time', 'RT-violation count']

    labels = [label for label, _ in results]
    avg_data = {phase: [] for phase in phases}
    max_data = {phase: [] for phase in phases}

    for _, stat in results:
        for phase in phases:
            if phase == 'RT-violation count':
                avg_data[phase].append(stat[phase])
            else:
                avg_data[phase].append(stat[phase][0])
                max_data[phase].append(stat[phase][1])

    fig, axes = plt.subplots(2, 4, figsize=(24, 12))
    axes = axes.flatten()

    x = np.arange(len(labels))
    width = 0.45

    for i, phase in enumerate(phases):
        ax = axes[i]
        if phase == 'RT-violation count':
        # Nur ein einzelner Balken
            ax.bar(x, avg_data[phase], width, color='gray', label='RT Violations')
        else:
            avg_vals = avg_data[phase]
            max_vals = max_data[phase]
            diff_vals = [max_v - avg_v for avg_v, max_v in zip(avg_vals, max_vals)]

            ax.bar(x, avg_vals, width, label='Avg', color='skyblue')
            ax.bar(x, diff_vals, width, bottom=avg_vals, label='Max - Avg', color='orange')

        ax.set_title(phase)
        ax.set_ylabel("ms" if phase != 'RT-violation count' else "Anzahl")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
        ax.grid(axis='y', linestyle='--', alpha=0.5)

        if i == 0:
            ax.legend()
    plt.tight_layout()
    plt.show()

def main():
    root_folder = "./results"  # Pfad zu deinem Hauptordner
    results = collect_all_results(root_folder)
    if not results:
        print("Keine Daten gefunden.")
    else:
        plot_dashboard(results)

if __name__ == "__main__":
    main()
