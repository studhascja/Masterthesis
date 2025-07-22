import subprocess
import threading
import time
import os
import signal
import shlex

CONFIG_PATH = "test_configuration" 

def run_iperf_server(process_container):
    iperf_cmd = ['iperf3', '-s', '-p', '5202']
    process = subprocess.Popen(iperf_cmd)
    process_container.append(process)

def run_config_script(param, process_container):
    filename = param if param else "hostapd.conf"
    interface = "wlan1"

    static_ip = "192.168.1.1"
    netmask = "255.255.255.0"

# Setze statische IP für wlan1
    subprocess.run(['ip', 'addr', 'flush', 'dev', interface])
    subprocess.run(['ip', 'addr', 'add', f'{static_ip}/24', 'dev', interface])
    subprocess.run(['ip', 'link', 'set', interface, 'up'])
    # Start hostapd
    hostapd_cmd = ['hostapd', f'/etc/hostapd/{filename}']
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

    time.sleep(5)

    # Starte Rust-Programm mit den ersten 4 Werten
    rust_args = ['./server', '--', val1, val2, val3, val4]
    rust_result = subprocess.run(rust_args, cwd='/code/server/target/debug')

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
    rust_build = ['cargo', 'build']
    rust_build_result = subprocess.run(rust_build, cwd='/code/server')
    iperf_process_container = []

    iperf_thread = threading.Thread(target=run_iperf_server, args=(iperf_process_container,))
    iperf_thread.start()

    with open(CONFIG_PATH, 'r') as file:
        for line in file:
            process_line(line)

    if iperf_process_container:
        print("Beende iperf_script.sh...")
        iperf_process = iperf_process_container[0]
        iperf_process.terminate()
        try:
            iperf_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            iperf_process.kill()

    iperf_thread.join()


if __name__ == '__main__':
    main()
