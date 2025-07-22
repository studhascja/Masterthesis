import matplotlib.pyplot as plt
import numpy as np

# Dummy-Daten
labels = [f"Test {i+1}" for i in range(5)]
phases = ['server_do', 'server_queue', 'server_send', 'client_do', 
	  'client_queue', 'client_send', 'cycle_time', 'RT-violation count']

data = {phase: np.random.uniform(1, 10, len(labels)) for phase in phases}

# Dashboard-Layout
fig, axes = plt.subplots(2, 4, figsize=(20, 10))
axes = axes.flatten()

for i, phase in enumerate(phases):
    ax = axes[i]
    ax.bar(labels, data[phase], color='skyblue')
    ax.set_title(f"Max Latenz – {phase}")
    ax.set_ylabel("ms")
    ax.set_xticklabels(labels, rotation=45)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

plt.tight_layout()
plt.show()

