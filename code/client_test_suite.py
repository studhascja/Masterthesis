import subprocess
import time
import os
import unittest
import re  # Importieren der `re`-Bibliothek für reguläre Ausdrücke

SSID = "jh_test"
PASSWORD = os.environ.get("WIFI_PASSWORD")
IFACE = "wlan1"

def connect_to_wifi():
    """Versucht, mit einem bestimmten WLAN zu verbinden."""
    attempt_counter = 0

    while True:
        attempt_counter += 1
        subprocess.run(["nmcli", "dev", "wifi", "connect", SSID, "password", PASSWORD, "ifname", IFACE])
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
            capture_output=True, text=True
        )
        if f"yes:{SSID}" in result.stdout:
            print(f"✅ Verbunden mit {SSID}")
            return
        elif attempt_counter % 5 == 0:
            print(f"Restart Networkmanager")
            subprocess.run(["iw", "reg", "set", "DE"])
            subprocess.run(["systemctl", "restart", "NetworkManager"])
        else:
            print(f"❌ Verbindung zu {SSID} fehlgeschlagen. Neuer Versuch...")
            time.sleep(5)

def disconnect_wifi():
    subprocess.run(["nmcli", "dev", "disconnect", IFACE])
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

def main():
    if PASSWORD is None:
        raise EnvironmentError("❌ Umgebungsvariable WIFI_PASSWORD ist nicht gesetzt!")

    subprocess.run(["iw", "reg", "set", "DE"])
    subprocess.run(["systemctl", "restart", "NetworkManager"])
    all_results = []
    with open("test_configuration", "r") as config:
        lines = config.readlines()

    for i, line in enumerate(lines):
        parts = line.strip().split()
        if len(parts) < 5:
            continue

        wifi_version = int(parts[0])
        freq = float(parts[1])
        bw = int(parts[2])

        print(f"\n🔁 Test {i+1}: SSID={SSID}, Standard=WiFi {wifi_version}, Freq={freq} GHz, Bandbreite={bw} MHz")

        connect_to_wifi()

        
        suite = unittest.TestSuite()
        test_bandwidth = WifiTest('test_bandwidth')
        test_freq = WifiTest('test_freq')
        test_version = WifiTest('test_version')
        test_bandwidth.configure(freq, bw, wifi_version)
        test_freq.configure(freq, bw, wifi_version)
        test_version.configure(freq, bw, wifi_version)
        suite.addTest(test_freq)
        suite.addTest(test_bandwidth)
        suite.addTest(test_version)
        #runner = unittest.TextTestRunner()
        result = unittest.TestResult()
        suite.run(result)
        all_results.append((i + 1, result))

        # Rust-Code ausführen
        os.chdir("/code/client")
        subprocess.run(["cargo", "run"])

        disconnect_wifi()

    print("\n📋 Gesamtergebnis der Testläufe:")
    for i, result in all_results:
        print(f"\n🧪 Testdurchlauf {i}:")
        total_tests = result.testsRun
        failed = len(result.failures)
        errored = len(result.errors)
        successful = total_tests - failed - errored

        print(f"  ✅ Erfolgreich: {successful}")
        print(f"  ❌ Fehler: {len(result.failures)}")
        for test, traceback in result.failures:
            print(f"    - Fehler in {test.id()}:")
            print(traceback)
        print(f"  💥 Fehlerhafte Ausführung: {len(result.errors)}")
        for test, traceback in result.errors:
            print(f"    - Fehler in {test.id()}:")
            print(traceback)

if __name__ == "__main__":
    main()
