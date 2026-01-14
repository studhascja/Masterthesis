import subprocess
import time
import os
import unittest
import re
import threading

# Wi-Fi configuration constants
SSID = "jh_test"
PASSWORD = os.environ.get("WIFI_PASSWORD")
IFACE = "wlan1"

# Reference to a running wpa_supplicant process
wpa_process = None

# Named pipe used to synchronize tests with the Rust client
pipe_path = "/tmp/notify_pipe"


def replace_wpa_conf(new_conf_path, interfaces_path="/etc/network/interfaces"):
    """
    Replaces the wpa-conf line inside /etc/network/interfaces
    with a new wpa_supplicant configuration path.
    """
    with open(interfaces_path, "r") as f:
        content = f.read()

    # Replace only the line starting with "wpa-conf"
    content = re.sub(
        r"^\s*wpa-conf\s+.*$",
        f"    wpa-conf {new_conf_path}",
        content,
        flags=re.MULTILINE
    )

    with open(interfaces_path, "w") as f:
        f.write(content)


def start_wpa_supplicant(wifi6):
    """
    Restarts wpa_supplicant and network interface configuration.

    wifi6: If True, use Wi-Fi 6 (802.11ax) configuration,
           otherwise use Wi-Fi 4/5 configuration.
    """
    global wpa_process

    # Kill any existing wpa_supplicant instances
    subprocess.run(["killall", "wpa_supplicant"])

    # Choose WPA configuration based on Wi-Fi version
    if wifi6:
        replace_wpa_conf("/code/wpa.conf")
    else:
        replace_wpa_conf("/code/wpa2.conf")

    # Restart the wireless network interface
    subprocess.run(["ifdown", IFACE])
    subprocess.run(["ifup", IFACE])


def connect_to_wifi(wifi6):
    """
    Attempts to connect to the configured SSID.
    Repeats until the connection is successful.
    """
    attempt_counter = 0

    while True:
        # Periodically restart wpa_supplicant to force reconnection
        if attempt_counter % 5 == 0:
            disconnect_wifi()
            thread = threading.Thread(
                target=start_wpa_supplicant,
                args=(wifi6,)
            )
            thread.start()

        time.sleep(10)
        attempt_counter += 1

        # Check current link status
        result = subprocess.run(
            ["iw", "dev", IFACE, "link"],
            capture_output=True,
            text=True
        )

        if SSID in result.stdout:
            print(f"✅ Connected to {SSID}")
            return
        else:
            print(f"❌ Failed to connect to {SSID}. Retrying...")


def disconnect_wifi():
    """
    Terminates wpa_supplicant and disconnects from the Wi-Fi network.
    """
    global wpa_process

    if wpa_process:
        wpa_process.terminate()
        wpa_process.wait()

    subprocess.run(["killall", "wpa_supplicant"])
    print("🔌 Wi-Fi disconnected.")
    time.sleep(2)


def get_bandwidth():
    """
    Retrieves the current channel bandwidth (in MHz)
    of the connected Wi-Fi interface.
    """
    try:
        output = subprocess.check_output(
            ["iw", "dev", IFACE, "info"],
            text=True
        )
        match = re.search(r'width:\s*(\d+)\s*(?=MHz)', output)
        if match:
            return int(match.group(1))
        return None
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute iw: {e}")
        return None


def get_wifi_band(frequency):
    """
    Determines the Wi-Fi band based on frequency in MHz.
    """
    if 2400 <= frequency <= 2500:
        return 2.4
    elif 5000 <= frequency <= 5900:
        return 5
    elif 5900 <= frequency <= 7100:
        return 6
    return None


def get_freq():
    """
    Retrieves the current Wi-Fi frequency band (2.4 / 5 / 6 GHz).
    """
    try:
        output = subprocess.check_output(
            ["iw", "dev", IFACE, "link"],
            text=True
        )
        match = re.search(r'freq:\s*(\d+\.\d+)', output)
        if match:
            frequency = float(match.group(1))
            return get_wifi_band(frequency)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute iw: {e}")
        return None


def get_prio():
    """
    Checks Linux scheduling priorities of client and iperf processes.

    Returns:
        (client_has_rt_prio, iperf_has_no_rt_prio)
    """
    try:
        output_client = subprocess.check_output(
            "ps -eLo comm,pri | grep client",
            shell=True,
            text=True
        )
        output_iperf = subprocess.check_output(
            "ps -eLo comm,pri | grep iperf",
            shell=True,
            text=True
        )

        client_ok = "139" in output_client
        iperf_ok = "139" not in output_iperf

        return client_ok, iperf_ok

    except subprocess.CalledProcessError as e:
        print(f"Failed to execute ps: {e}")
        return False, False


def get_wifi_version():
    """
    Determines the Wi-Fi standard currently in use.

    Returns:
        6 for Wi-Fi 6 (HE)
        5 for Wi-Fi 5 (VHT)
        4 for Wi-Fi 4 (HT)
    """
    try:
        output = subprocess.check_output(
            ["iw", "dev", IFACE, "link"],
            text=True
        ).lower()

        if "he" in output:
            return 6
        elif "vht" in output:
            return 5
        return 4
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute iw: {e}")
        return None


class WifiTest(unittest.TestCase):
    """
    Collection of unittests validating Wi-Fi parameters
    and process scheduling priorities.
    """

    def configure(self, freq, bw, version):
        """
        Stores expected values for subsequent test cases.
        """
        self.freq_expected = freq
        self.bw_expected = bw
        self.version_expected = version

    def test_bandwidth(self):
        bandwidth = get_bandwidth()
        self.assertEqual(self.bw_expected, bandwidth)

    def test_freq(self):
        freq = get_freq()
        self.assertEqual(self.freq_expected, freq)

    def test_version(self):
        version = get_wifi_version()
        self.assertEqual(self.version_expected, version)

    def test_prio(self):
        client_prio, iperf_prio = get_prio()
        self.assertTrue(client_prio)
        self.assertTrue(iperf_prio)


def run_rust_udp(process_container, duration, throughput, size):
    """
    Runs the Rust UDP client and waits for completion.
    """
    rust_cmd = [
        "./client_udp/target/release/client_udp",
        throughput, duration, size
    ]
    process = subprocess.Popen(rust_cmd)
    process_container.append(process)
    process.wait()


def run_rust_tcp(process_container, duration, throughput, size):
    """
    Runs the Rust TCP client and waits for completion.
    """
    rust_cmd = [
        "./client/target/release/client",
        throughput, duration, size
    ]
    process = subprocess.Popen(rust_cmd)
    process_container.append(process)
    process.wait()


def main():
    """
    Main test orchestration:
    - Build Rust clients
    - Connect to Wi-Fi
    - Run traffic generation
    - Validate Wi-Fi parameters using unittest
    """
    if PASSWORD is None:
        raise EnvironmentError("❌ WIFI_PASSWORD environment variable is not set!")

    # Build Rust clients
    subprocess.run(['cargo', 'build', '--release'], cwd='/code/client_udp')
    subprocess.run(['cargo', 'build', '--release'], cwd='/code/client')

    # Set regulatory domain
    subprocess.run(["iw", "reg", "set", "DE"])

    all_results = []

    # Load test configuration
    with open("test_configuration", "r") as config:
        lines = config.readlines()

    # Resume test execution from status file
    with open("status", "r") as status_file:
        n = int(status_file.read().strip())

    while n <= len(lines):
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())

        line = lines[n - 1].strip()
        parts = line.split()
        if len(parts) < 7:
            continue

        config_file = parts[0]
        with open(config_file, "r") as cfg:
            duration, throughput, size = cfg.readline().split()

        wifi_version = int(parts[1])
        freq = float(parts[2])
        bw = int(parts[3])

        print(
            f"\n🔁 Test {n}: SSID={SSID}, "
            f"WiFi {wifi_version}, "
            f"Freq={freq} GHz, "
            f"Bandwidth={bw} MHz"
        )

        # Connect to Wi-Fi
        connect_to_wifi(wifi6=(wifi_version == 6))

        # QoS setup
        if parts[4] == "1":
            subprocess.run(['bash', 'setup_qos.sh'])
        else:
            subprocess.run(['bash', 'clean_qos.sh'])

        # Start Rust traffic generator
        rust_process_container = []
        if parts[5] == "udp":
            rust_thread = threading.Thread(
                target=run_rust_udp,
                args=(rust_process_container, duration, throughput, size)
            )
        else:
            rust_thread = threading.Thread(
                target=run_rust_tcp,
                args=(rust_process_container, duration, throughput, size)
            )

        rust_thread.start()

        # Create named pipe if needed
        if not os.path.exists(pipe_path):
            os.mkfifo(pipe_path)

        # Wait for START signal from Rust process
        with open(pipe_path, 'r') as pipe:
            while True:
                line = pipe.readline()
                if line.strip() == "START":
                    suite = unittest.TestSuite()

                    test_bw = WifiTest('test_bandwidth')
                    test_freq = WifiTest('test_freq')
                    test_ver = WifiTest('test_version')
                    test_prio = WifiTest('test_prio')

                    test_bw.configure(freq, bw, wifi_version)
                    test_freq.configure(freq, bw, wifi_version)
                    test_ver.configure(freq, bw, wifi_version)

                    suite.addTest(test_freq)
                    suite.addTest(test_bw)
                    suite.addTest(test_ver)
                    suite.addTest(test_prio)

                    result = unittest.TestResult()
                    suite.run(result)
                    all_results.append((n, result))

                    rust_thread.join()

                    with open("status", "w", encoding="utf-8") as f:
                        f.write(str(n + 1))

                    disconnect_wifi()
                    break

        if n + 1 > len(lines):
            break

    # Reset status file
    with open("status", "w", encoding="utf-8") as f:
        f.write("1")

    # Write test summary
    output_file = "test_results"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\nOverall test results:\n")

        for i, result in all_results:
            f.write(f"\nTest run {i}:\n")
            total = result.testsRun
            failed = len(result.failures)
            errors = len(result.errors)
            success = total - failed - errors

            f.write(f"  Successful: {success}\n")
            f.write(f"  Failures: {failed}\n")
            f.write(f"  Errors: {errors}\n")


if __name__ == "__main__":
    main()
