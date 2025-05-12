import subprocess
import threading
import time
import os
import signal

CONFIG_PATH = "test_configurations.save"  # Dateiname mit den Konfigurationszeilen

def run_config_script(param, process_container):
    import shlex

    filename = param if param else "hostapd.conf"
    config_file = "/etc/dnsmasq.conf"
    interface = "wlp1s0"
    dhcp_range = "dhcp-range=192.168.1.10,192.168.1.100,12h"

    # Configure DHCP-Server
    with open(config_file, 'r') as f:
        content = f.read()
    if f"interface={interface}" not in content:
        subprocess.run(['sudo', 'tee', '-a', config_file], input=f"interface={interface}\n", text=True)
    if dhcp_range not in content:
        subprocess.run(['sudo', 'tee', '-a', config_file], input=f"{dhcp_range}\n", text=True)
    print("Configured DHCP-server")

    # Configure network interface
    subprocess.run(['sudo', 'ifconfig', interface, '192.168.1.1', 'netmask', '255.255.255.0', 'up'])
    print("Configure Interface")

    # Stop systemd-resolved if running
    result = subprocess.run(['systemctl', 'is-active', '--quiet', 'systemd-resolved'])
    if result.returncode == 0:
        subprocess.run(['sudo', 'systemctl', 'stop', 'systemd-resolved'])
        print("Stopped systemd-resolved.")

    # Restart dnsmasq
    subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'])
    print("Started Dnsmasq.")

    # Start hostapd
    hostapd_cmd = ['sudo', '/home/jakob/hostapd-2.11/hostapd/hostapd', '-dd', f'/etc/hostapd/{filename}']
    process = subprocess.Popen(hostapd_cmd)
    process_container.append(process)


def process_line(line):
    parts = line.strip().split()
    if len(parts) != 5:
        print(f"Überspringe ungültige Zeile: {line}")
        return

    val1, val2, val3, val4, param = parts

    config_process_container = []

    # Starte config-script.sh mit dem Parameter aus Spalte 5
    config_thread = threading.Thread(target=run_config_script, args=(param, config_process_container))
    config_thread.start()

    # Warte kurz, um sicherzustellen, dass das Script läuft
    time.sleep(5)

    # Starte Rust-Programm mit den ersten 4 Werten
    rust_args = ['cargo', 'run', '--', val1, val2, val3, val4]
    rust_result = subprocess.run(rust_args, cwd='/home/jakob/Masterthesis/code/server')

    # config-script.sh beenden
    if config_process_container:
        print("Beende config_script.sh...")
        config_process = config_process_container[0]
        config_process.terminate()
        try:
            config_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("config_script.sh reagiert nicht, erzwinge Kill...")
            config_process.kill()

    config_thread.join()

    # clean-script.sh aufrufen
    subprocess.run(['bash', 'clean-script.sh'])

def main():
    with open(CONFIG_PATH, 'r') as file:
        for line in file:
            process_line(line)

if __name__ == '__main__':
    main()
