import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import RegularPolygon, Circle
from matplotlib.path import Path
from matplotlib.projections.polar import PolarAxes
from matplotlib.projections import register_projection
from matplotlib.spines import Spine
from matplotlib.transforms import Affine2D

# -------------------------
# Radar Factory
# -------------------------
def radar_factory(num_vars, frame='polygon'):
    theta = np.linspace(0, 2 * np.pi, num_vars, endpoint=False)

    class RadarAxes(PolarAxes):
        name = 'radar'

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.set_theta_zero_location('N')

        def fill(self, *args, closed=True, **kwargs):
            return super().fill(closed=closed, *args, **kwargs)

        def plot(self, *args, **kwargs):
            lines = super().plot(*args, **kwargs)
            for line in lines:
                self._close_line(line)

        def _close_line(self, line):
            x, y = line.get_data()
            if x[0] != x[-1]:
                x = np.concatenate((x, [x[0]]))
                y = np.concatenate((y, [y[0]]))
                line.set_data(x, y)

        def set_varlabels(self, labels):
            self.set_thetagrids(np.degrees(theta), labels)

        def _gen_axes_patch(self):
            if frame == 'circle':
                return Circle((0.5, 0.5), 0.5)
            elif frame == 'polygon':
                return RegularPolygon((0.5, 0.5), num_vars, radius=.5, edgecolor="k")
            else:
                raise ValueError("Unbekanntes Frame: %s" % frame)

        def draw(self, renderer):
            if frame == 'polygon':
                for gl in self.yaxis.get_gridlines():
                    gl.get_path()._interpolation_steps = num_vars
            super().draw(renderer)

        def set_rgrids(self, radii, labels=None, angle=22.5, **kwargs):
            grids = super().set_rgrids(radii, labels=labels, angle=angle, **kwargs)
            if frame == 'polygon':
                for gl in self.yaxis.get_gridlines():
                    gl.get_path()._interpolation_steps = num_vars
            return grids

        def _gen_axes_spines(self):
            if frame == 'circle':
                return super()._gen_axes_spines()
            elif frame == 'polygon':
                spine = Spine(self, 'circle', Path.unit_regular_polygon(num_vars))
                spine.set_transform(Affine2D().scale(.5).translate(.5, .5) + self.transAxes)
                return {'polar': spine}
            else:
                raise ValueError("Unbekanntes Frame: %s" % frame)

    register_projection(RadarAxes)
    return theta

# -------------------------
# Daten laden
# -------------------------
def load_latency_data(config):
    BASE_DIR = config + "/results"
    latency_data = {}
    for root, dirs, files in os.walk(BASE_DIR):
        for file in files:
            if file == "latencys_0":
                path = os.path.join(root, file)
                parts = path.split(os.sep)
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
                    latency_data[key] = np.max(rtts)
    return latency_data

# -------------------------
# Prozentuale Differenzen pro Stufe (nur ein Wert pro Stufe)
# -------------------------
def stufen_percent_diff(data, factor_index, factor_name):
    keys = list(data.keys())
    stufen_values = {}
    for key in keys:
        stufe = key[factor_index]
        if stufe not in stufen_values:
            stufen_values[stufe] = []
        # Vergleiche mit allen anderen Stufen desselben Faktors
        for other_key in keys:
            if key == other_key:
                continue
            if all((a == b) if idx != factor_index else True for idx, (a,b) in enumerate(zip(key, other_key))):
                v1, v2 = data[key], data[other_key]
                if v1 > 0 and v2 > 0:
                    percent = (v2 - v1) / v1 * 100
                    stufen_values[stufe].append(percent)
    # Mittelwert pro Stufe
    stufen_avg = {}
    for stufe, vals in stufen_values.items():
        vals = np.array(vals)
        avg = vals.mean() if len(vals) > 0 else 0
        stufen_avg[stufe] = avg  # nur ein Punkt pro Stufe
    return stufen_avg

# -------------------------
# Durchschnitt pro Faktor (Linie)
# -------------------------
def mean_percent_diff_for_factor(data, factor_index):
    keys = list(data.keys())
    diffs = []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            k1, k2 = keys[i], keys[j]
            if all((a == b) if idx != factor_index else (a != b) for idx, (a,b) in enumerate(zip(k1,k2))):
                v1, v2 = data[k1], data[k2]
                if v1 > 0 and v2 > 0:
                    percent = abs(v2 - v1)/((v1 + v2)/2) * 100
                    diffs.append(percent)
    return np.mean(diffs) if diffs else 0

# -------------------------
# Faktoren
# -------------------------
factors = ["Standard", "Frequenz", "Bandbreite", "QoS", "Protokoll"]
factor_indices = {f:i for i,f in enumerate(factors)}

# -------------------------
# Radarplot
# -------------------------
def radar_chart(labels, values_list, titles, stufen_list):
    N = len(labels)
    theta = radar_factory(N, frame='polygon')
    fig, ax = plt.subplots(figsize=(9,9), subplot_kw=dict(projection='radar'))
    fig.subplots_adjust(top=0.85, bottom=0.05)

    max_val = 200
    step = 50
    rgrid = np.arange(0, max_val+step, step)
    ax.set_rgrids(rgrid, labels=[f"{int(v)}%" for v in rgrid])
    ax.set_title("Durchschnittliche prozentuale Unterschiede und Stufen", position=(0.5,1.1), ha='center')

    # Linien für jede Config
    for values, title in zip(values_list, titles):
        ax.plot(theta, values, label=title)
        ax.fill(theta, values, alpha=0.25)

    # Marker pro Stufe
    for i, factor in enumerate(labels):
        stufen_data = stufen_list[i]
        for stufe, avg in stufen_data.items():
            color = 'green' if avg >=0 else 'red'
            ax.plot(theta[i], abs(avg), 'o', color=color)
            ax.text(theta[i], abs(avg)+5, f"{stufe}: {avg:+.0f}%", ha='center', fontsize=8, color=color)

    ax.set_varlabels(labels)
    plt.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))
    plt.show()

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    config1 = input("Welche erste Config soll geplottet werden? (z.B. 1): ").strip()
    config2 = input("Welche zweite Config soll geplottet werden? (z.B. 2): ").strip()

    data1 = load_latency_data(config1)
    data2 = load_latency_data(config2)

    results1 = [mean_percent_diff_for_factor(data1, factor_indices[f]) for f in factors]
    results2 = [mean_percent_diff_for_factor(data2, factor_indices[f]) for f in factors]

    stufen_list = []
    for f in factors:
        stufen1 = stufen_percent_diff(data1, factor_indices[f], f)
        stufen2 = stufen_percent_diff(data2, factor_indices[f], f)
        # kombiniere beide Configs, Mittelwert pro Stufe
        combined = {}
        for stufe in set(list(stufen1.keys()) + list(stufen2.keys())):
            vals = []
            if stufe in stufen1: vals.append(stufen1[stufe])
            if stufe in stufen2: vals.append(stufen2[stufe])
            combined[stufe] = np.mean(vals)
        stufen_list.append(combined)

    radar_chart(factors, [results1, results2],
                [f"Config {config1}", f"Config {config2}"],
                stufen_list)
