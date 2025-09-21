import subprocess
import threading
import time
import os
import signal
import shlex
import unittest

CONFIG_PATH = "test_configuration" 
all_results = []


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

def run_rust_udp(process_container, val0, val1, val2, val3, val4, val5):
    rust_result = ['./server_udp/target/debug/server_udp', val0, str(val1), str(val2), str(val3), str(val4), val5]
    process = subprocess.Popen(rust_result)
    process_container.append(process)
    process.wait()

def run_rust_tcp(process_container, val0, val1, val2, val3, val4, val5):
    rust_result = ['./server/target/debug/server', str(val0), str(val1), str(val2), str(val3), str(val4), val5]
    process = subprocess.Popen(rust_result)
    process_container.append(process)
    process.wait()

def process_line(line, index):
    global all_results
    parts = line.strip().split()
    if len(parts) != 7:
        print(f" ^|berspringe ung  ltige Zeile: {line}")
        return

    val0, val1, val2, val3, val4, val5, param = parts
    
    with open(val0, "r") as config:
        c_line = config.readline()
   
    c_parts = c_line.strip().split()
    duration, throughput = c_parts

    config_process_container = []
    if val4 == "1":
        print(f"Start QoS")
        subprocess.run(['bash', 'setup_qos.sh'])
    else:
        print(f"Lösche QoS Config")
        subprocess.run(['bash', 'clean_qos.sh'])
    # Starte config-script.sh mit dem Parameter aus Spalte 5
    config_thread = threading.Thread(target=run_config_script, args=(param, config_process_container))
    config_thread.start()

    time.sleep(5)

    rust_process_container = []

    if val5 == "udp":
        rust_thread = threading.Thread(target=run_rust_udp, args=(rust_process_container, val0, val1, val2, val3, val4, duration))
        rust_thread.start()
    else:
        rust_thread = threading.Thread(target=run_rust_tcp, args=(rust_process_container, val0, val1, val2, val3, val4, duration))
        rust_thread.start()

    suite = unittest.TestSuite()
    test_prio = WifiTest('test_prio')
    suite.addTest(test_prio)
    result = unittest.TestResult()
    suite.run(result)
    all_results.append((index + 1, result))

    rust_thread.join()

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

def get_prio():
    try:
        output_server = subprocess.check_output("ps -eLo comm,pri | grep server", shell=True, text=True)
        output_iperf = subprocess.check_output("ps -eLo comm,pri | grep iperf", shell=True, text=True)
        result_server = False
        result_iperf = False

        if "139" in output_server:
            result_server = True
        if "139" not in output_iperf:
            result_iperf = True

        return result_server, result_iperf

    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Ausf  hren von iw: {e}")
        return False, False

class WifiTest(unittest.TestCase):

    def test_prio(self):
        server_prio, iperf_prio = get_prio()
        self.assertTrue(server_prio)
        self.assertTrue(iperf_prio)


def main():
    global all_results
    rust_build = ['cargo', 'build']
    rust_udp_build_result = subprocess.run(rust_build, cwd='/code/server_udp')
    rust_tcp_build_result = subprocess.run(rust_build, cwd='/code/server')
    iperf_process_container = []

    iperf_thread = threading.Thread(target=run_iperf_server, args=(iperf_process_container,))
    iperf_thread.start()

    with open("test_configuration", "r") as config:
        lines = config.readlines()
 
    with open("status", "r") as status_file:
        n = int(status_file.read().strip())
        if n > len(lines):
            with open(output_file, "w", encoding="utf-8") as f:
                        f.write(str(1))
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())
            
    while n < len(lines):
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())
            
        line = lines[n-1].strip()
        process_line(line, n-1)
        with open("status", "w", encoding="utf-8") as f:
            f.write(str(n + 1))

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

with open("status", "w", encoding="utf-8") as f:
    f.write(str(1))

output_file = "test_results"

with open(output_file, "w", encoding="utf-8") as f:
    f.write("\n📋 Gesamtergebnis der Testläufe:\n")
    
    for i, result in all_results:
        f.write(f"\n^= Testdurchlauf {i}:\n")
        total_tests = result.testsRun
        failed = len(result.failures)
        errored = len(result.errors)
        successful = total_tests - failed - errored

        f.write(f"  ✅ Erfolgreich: {successful}\n")
        f.write(f"  ❌ Fehler: {failed}\n")
        for test, traceback in result.failures:
            f.write(f"    - Fehler in {test.id()}:\n")
            f.write(f"{traceback}\n")
        
        f.write(f"  💥 Fehlerhafte Ausführung: {errored}\n")
        for test, traceback in result.errors:
            f.write(f"    - Fehler in {test.id()}:\n")
            f.write(f"{traceback}\n")


led_path = "/sys/class/leds/ACT/brightness"

def led_on():
    with open(led_path, "w") as f:
        f.write("1")

def led_off():
    with open(led_path, "w") as f:
        f.write("0")

while True:
    led_on()
    time.sleep(0.5)
    led_off()
    time.sleep(0.5)
