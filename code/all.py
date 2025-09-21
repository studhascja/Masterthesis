import os
import numpy as np
import pandas as pd
import plotly.graph_objs as go
import dash
from dash import dcc, html

# --- Deine bestehenden Funktionen bleiben unverändert ---
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

    def avg_max(values):
        return (sum(values) / len(values) / 1_000_000, max(values) / 1_000_000)

    stats = {
        'server_do': avg_max(server_do),
        'server_queue': avg_max(server_queue),
        'server_send': avg_max(server_send),
        'client_do': avg_max(client_do),
        'client_queue': avg_max(client_queue),
        'client_send': avg_max(client_send),
        'cycle_time': avg_max(cycle_times),
        'RT-violation count': sum(1 for c in cycle_times if c / 1_000_000 > 3)
    }
    return stats

def read_latencys_file(filepath):
    latencies = []
    with open(filepath, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 7:
                latencies.append(tuple(map(int, parts[:7])))
    return latencies

def collect_all_results(root_folders):
    all_results = {}  # {config_number: results_list}
    for folder in root_folders:
        results = []
        if not os.path.exists(folder):
            continue
        for dirpath, _, filenames in os.walk(folder):
            if "latencys_0" in filenames:
                full_path = os.path.join(dirpath, "latencys_0")
                latencies = read_latencys_file(full_path)
                stats = calculate_latency_statistics(latencies)
                if not stats:
                    continue
                parts = dirpath.split(os.sep)
                try:
                    standard = parts[-5].replace("standard_", "")
                    frequency = parts[-4].replace("frequency_", "")
                    bandwidth = parts[-3].replace("bandwith_", "")
                    qos = parts[-2].replace("qos_", "")
                    protocoll = parts[-1]
                    label = f"{standard}-{frequency}-{bandwidth}-{qos}-{protocoll}"
                except IndexError:
                    label = dirpath
                results.append((label, stats))
        all_results[folder] = results
    return all_results

def filter_results(results, protocol):
    return [(label, stat) for label, stat in results if protocol in label.lower()]

# --- Dashboard-Funktion ---
def build_dashboard(protocol_results, title):
    phases = ['server_do', 'server_queue', 'server_send',
              'client_do', 'client_queue', 'client_send',
              'cycle_time', 'RT-violation count']

    labels = [label for label, _ in protocol_results]
    avg_data = {phase: [] for phase in phases}
    max_data = {phase: [] for phase in phases}

    for _, stat in protocol_results:
        for phase in phases:
            if phase == 'RT-violation count':
                avg_data[phase].append(stat[phase])
            else:
                avg, max_val = stat[phase]
                avg_data[phase].append(avg)
                max_data[phase].append(max_val)

    graphs = []
    for phase in phases:
        if phase == 'RT-violation count':
            trace = go.Bar(
                x=labels,
                y=avg_data[phase],
                name='RT Violations',
                marker_color='gray'
            )
            layout = go.Layout(title=phase, xaxis_tickangle=-45)
            fig = go.Figure(data=[trace], layout=layout)
        else:
            avg_vals = avg_data[phase]
            diff_vals = [max_v - avg_v for avg_v, max_v in zip(avg_vals, max_data[phase])]
            trace1 = go.Bar(x=labels, y=avg_vals, name='Avg', marker_color='skyblue')
            trace2 = go.Bar(x=labels, y=diff_vals, name='Max - Avg', marker_color='orange')
            layout = go.Layout(barmode='stack', title=phase, xaxis_tickangle=-45)
            fig = go.Figure(data=[trace1, trace2], layout=layout)

        graphs.append(dcc.Graph(figure=fig))

    return html.Div([html.H2(title), *graphs])

# --- Dash App ---
def run_dash_app(all_results):
    app = dash.Dash(__name__)
    app.title = "UDP/TCP Dashboard"

    tabs = []
    for config, results in all_results.items():
        udp_results = filter_results(results, 'udp')
        tcp_results = filter_results(results, 'tcp')

        tabs.append(dcc.Tab(label=f"Config {os.path.basename(config)}", children=[
            dcc.Tabs([
                dcc.Tab(label="UDP", children=[build_dashboard(udp_results, "UDP")]),
                dcc.Tab(label="TCP", children=[build_dashboard(tcp_results, "TCP")])
            ])
        ]))

    app.layout = html.Div([
        html.H1("UDP / TCP Dashboard", style={"textAlign": "center"}),
        dcc.Tabs(tabs)
    ])

    app.run(debug=True)

# --- Main ---
def main():
    root_folders = ["1/results", "2/results", "3/results"]
    all_results = collect_all_results(root_folders)

    if not all_results:
        print("Keine Daten gefunden.")
        return

    run_dash_app(all_results)

if __name__ == "__main__":
    main()
