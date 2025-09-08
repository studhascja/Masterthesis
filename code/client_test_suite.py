import subprocess
import time
import os
import unittest
import re  
import threading

SSID = "jh_test"
PASSWORD = os.environ.get("WIFI_PASSWORD")
IFACE = "wlan1"
wpa_process = None  
pipe_path = "/tmp/notify_pipe"

def replace_wpa_conf(new_conf_path, interfaces_path="/etc/network/interfaces"):
    with open(interfaces_path, "r") as f:
        content = f.read()

    # Ersetze nur die Zeile, die mit "wpa-conf" beginnt
    content = re.sub(r"^\s*wpa-conf\s+.*$", f"    wpa-conf {new_conf_path}", content, flags=re.MULTILINE)

    with open(interfaces_path, "w") as f:
        f.write(content)


def start_wpa_supplicant(wifi6):
    global wpa_process
    subprocess.run(["killall", "wpa_supplicant"])

    if wifi6:
        replace_wpa_conf("/code/wpa.conf")
    else:
         replace_wpa_conf("/code/wpa2.conf")
    
    subprocess.run(["ifdown", IFACE])
    subprocess.run(["ifup", IFACE])

def connect_to_wifi(wifi6):
    """Versucht, mit einem bestimmten WLAN zu verbinden."""
    attempt_counter = 0
    while True:
        if attempt_counter % 5 == 0:
             disconnect_wifi()
             thread = threading.Thread(target=start_wpa_supplicant, args=(wifi6,))
             thread.start()
        time.sleep(10)
        attempt_counter = attempt_counter + 1
        result = subprocess.run(
            ["iw", "dev", IFACE, "link"],
            capture_output=True, text=True
        )
        if f"{SSID}" in result.stdout:
            print(f"✅ Verbunden mit {SSID}")
            return
        else:
            print(f"❌ Verbindung zu {SSID} fehlgeschlagen. Neuer Versuch...")

def disconnect_wifi():
    global wpa_process
    if wpa_process:
        wpa_process.terminate()
        wpa_process.wait()
    subprocess.run(["killall", "wpa_supplicant"])
    print("🔌 Verbindung getrennt.")
    time.sleep(2)

def get_bandwidth():
    try:
        output = subprocess.check_output(["iw", "dev", IFACE, "info"], text=True)
        match = re.search(r'width:\s*(\d+)\s*(?=MHz)', output)
        if match:
            return int(match.group(1))  
        else:
            return None
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Ausführen von iw: {e}")
        return None

def get_wifi_band(frequency):
    # 2.4 GHz Band
    if 2400 <= frequency <= 2500:
        return 2.4
    # 5 GHz Band
    elif 5000 <= frequency <= 5900:
        return 5
    # 6 GHz Band (Wi-Fi 6E)
    elif 5900 <= frequency <= 7100:
        return 6
    else:
        return None

def get_freq():
    try:
        output = subprocess.check_output(["iw", "dev", IFACE, "link"], text=True)
        match = re.search(r'freq:\s*(\d+\.\d+)', output)
        if match:
            frequency = float(match.group(1))
            band = get_wifi_band(frequency)
            return band
        else:
            return None
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Ausführen von iw: {e}")
        return None

def get_prio():
    try:
        output_client = subprocess.check_output("ps -eLo comm,pri | grep client", shell=True, text=True)
        output_iperf = subprocess.check_output("ps -eLo comm,pri | grep iperf", shell=True, text=True)    
        result_client = False
        result_iperf = False

        if "139" in output_client:
            result_client = True
        if "139" not in output_iperf:
            result_iperf = True

        return result_client, result_iperf
    
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Ausf  hren von ps: {e}")
        return False, False

def get_wifi_version():
    try:
        output = subprocess.check_output(["iw", "dev", IFACE, "link"], text=True).lower()

        if "he" in output:
            return 6
        elif "vht" in output:
            return 5
        else:
            return 4
    except subprocess.CalledProcessError as e:
        print(f"Fehler beim Ausführen von iw: {e}")
        return None


class WifiTest(unittest.TestCase):

    def test_bandwidth(self):
        bandwidth = get_bandwidth()
        self.assertEqual(self.bw_expected, bandwidth)  

    def test_freq(self):
        freq = get_freq()
        self.assertEqual(self.freq_expected, freq)

    def test_version(self):
        version = get_wifi_version()
        self.assertEqual(self.version_expected, version)

    def configure(self, freq, bw, version):
        self.freq_expected = freq
        self.bw_expected = bw
        self.version_expected = version

    def test_prio(self):
        client_prio, iperf_prio = get_prio()
        self.assertTrue(client_prio)
        self.assertTrue(iperf_prio)

def run_rust_udp(process_container):
        rust_result = ["./client_udp/target/debug/client_udp", "15M", "12"]
        process = subprocess.Popen(rust_result)
        process_container.append(process)
        process.wait()

def run_rust_tcp(process_container):
        rust_result = ["./client/target/debug/client", "15M", "12"]
        process = subprocess.Popen(rust_result)
        process_container.append(process)
        process.wait()

def main():
    if PASSWORD is None:
        raise EnvironmentError("❌ Umgebungsvariable WIFI_PASSWORD ist nicht gesetzt!")
    
    rust_build = ['cargo', 'build']
    rust_udp_build_result = subprocess.run(rust_build, cwd='/code/client_udp')
    rust_tcp_build_result = subprocess.run(rust_build, cwd='/code/client')

    subprocess.run(["iw", "reg", "set", "DE"])
    all_results = []
        
    with open("test_configuration", "r") as config:
        lines = config.readlines()

    with open("status", "r") as status_file:
        n = int(status_file.read().strip())
        if n > len(lines):
            with open(output_file, "w", encoding="utf-8") as f:
                        f.write(str(1))
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())
            
    while n <= len(lines):
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())
        

        line = lines[n-1].strip()
        parts = line.strip().split()
        if len(parts) < 6:
            continue

        wifi_version = int(parts[0])
        freq = float(parts[1])
        bw = int(parts[2])

        print(f"\n🔁 Test {n}: SSID={SSID}, Standard=WiFi {wifi_version}, Freq={freq} GHz, Bandbreite={bw} MHz")
	
        if wifi_version == 6:
                connect_to_wifi(1)
        else:
                connect_to_wifi(0)
        if parts[3] == "1":
            print("Starte QoS...")
           # subprocess.run(['bash', 'setup_qos.sh'])
        else:
            print("Lösche QoS Config...")
            subprocess.run(['bash', 'clean_qos.sh'])
       
        rust_process_container = []

        if parts[4] == "udp":
            rust_thread = threading.Thread(target=run_rust_udp, args=(rust_process_container,))
        else:
            rust_thread = threading.Thread(target=run_rust_tcp, args=(rust_process_container,))
	
        rust_thread.start()
        if not os.path.exists(pipe_path):
            os.mkfifo(pipe_path)  # Erstellt die named pipe

        with open(pipe_path, 'r') as pipe:
            while True:
                line = pipe.readline()
                if line.strip() == "START":
                    
                    suite = unittest.TestSuite()
                    test_bandwidth = WifiTest('test_bandwidth')
                    test_freq = WifiTest('test_freq')
                    test_version = WifiTest('test_version')
                    test_prio = WifiTest('test_prio')
                    test_bandwidth.configure(freq, bw, wifi_version)
                    test_freq.configure(freq, bw, wifi_version)
                    test_version.configure(freq, bw, wifi_version)
                    suite.addTest(test_freq)
                    suite.addTest(test_bandwidth)
                    suite.addTest(test_version)
                    suite.addTest(test_prio)
                    result = unittest.TestResult()
                    suite.run(result)
                    all_results.append((n, result))

                    rust_thread.join()
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(str(n + 1))

                    disconnect_wifi()

                    break
        if n+1 > len(lines):
            break

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


if __name__ == "__main__":
    main()
