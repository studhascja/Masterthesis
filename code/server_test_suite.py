import subprocess
import threading
import time
import os
import signal
import shlex
import unittest

# Path to the test configuration file
CONFIG_PATH = "test_configuration"

# Global list collecting all unittest results
all_results = []


def run_iperf_server(process_container):
    """
    Starts an iperf3 server on TCP/UDP port 5202.
    The process handle is stored in process_container
    so it can be terminated later.
    """
    iperf_cmd = ['iperf3', '-s', '-p', '5202']
    process = subprocess.Popen(iperf_cmd)
    process_container.append(process)


def run_config_script(param, process_container):
    """
    Configures the wireless interface and starts hostapd.

    param:        Name of the hostapd configuration file
    process_container: List used to store the hostapd process
    """
    filename = param if param else "hostapd.conf"
    interface = "wlan1"

    static_ip = "192.168.1.1"
    netmask = "255.255.255.0"

    # Configure a static IP address on wlan1 (used Wi-Fi AP)
    subprocess.run(['ip', 'addr', 'flush', 'dev', interface])
    subprocess.run(['ip', 'addr', 'add', f'{static_ip}/24', 'dev', interface])
    subprocess.run(['ip', 'link', 'set', interface, 'up'])

    # Start hostapd with the selected configuration file
    hostapd_cmd = ['hostapd', f'/etc/hostapd/{filename}']
    process = subprocess.Popen(hostapd_cmd)
    process_container.append(process)


def run_rust_udp(process_container, val0, val1, val2, val3, val4, val5):
    """
    Starts the Rust UDP server with the given arguments.
    Blocks until the process terminates.
    """
    rust_result = [
        './server_udp/target/release/server_udp',
        val0, str(val1), str(val2), str(val3), str(val4), val5
    ]
    process = subprocess.Popen(rust_result)
    process_container.append(process)
    process.wait()


def run_rust_tcp(process_container, val0, val1, val2, val3, val4, val5):
    """
    Starts the Rust TCP server with the given arguments.
    Blocks until the process terminates.
    """
    rust_result = [
        './server/target/release/server',
        str(val0), str(val1), str(val2), str(val3), str(val4), val5
    ]
    process = subprocess.Popen(rust_result)
    process_container.append(process)
    process.wait()


def process_line(line, index):
    """
    Processes a single line from the test configuration file.
    Executes one full test run including:
      - QoS setup
      - AP configuration
      - Rust server execution
      - Priority validation via unittest
    """
    global all_results

    parts = line.strip().split()
    if len(parts) != 7:
        print(f"Skipping invalid line: {line}")
        return

    val0, val1, val2, val3, val4, val5, param = parts

    # Read test duration and throughput from the referenced file
    with open(val0, "r") as config:
        c_line = config.readline()

    duration, throughput = c_line.strip().split()

    # Enable or disable QoS depending on configuration
    if val4 == "1":
        print("Enabling QoS")
        subprocess.run(['bash', 'setup_qos.sh'])
    else:
        print("Disabling QoS")
        subprocess.run(['bash', 'clean_qos.sh'])

    # Start AP configuration / hostapd in a separate thread
    config_process_container = []
    config_thread = threading.Thread(
        target=run_config_script,
        args=(param, config_process_container)
    )
    config_thread.start()

    # Allow WLAN setup to stabilize
    time.sleep(5)

    # Start Rust server (UDP or TCP) in a separate thread
    rust_process_container = []

    if val5 == "udp":
        rust_thread = threading.Thread(
            target=run_rust_udp,
            args=(rust_process_container, val0, val1, val2, val3, val4, duration)
        )
    else:
        rust_thread = threading.Thread(
            target=run_rust_tcp,
            args=(rust_process_container, val0, val1, val2, val3, val4, duration)
        )

    rust_thread.start()

    # Execute unittest to validate process priorities
    suite = unittest.TestSuite()
    test_prio = WifiTest('test_prio')
    suite.addTest(test_prio)

    result = unittest.TestResult()
    suite.run(result)

    # Store test result
    all_results.append((index + 1, result))

    # Wait for Rust server to exit
    rust_thread.join()

    # Stop hostapd / AP configuration
    if config_process_container:
        print("Stopping hostapd...")
        config_process = config_process_container[0]
        config_process.terminate()
        try:
            config_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Hostapd did not terminate, forcing kill")
            config_process.kill()

    config_thread.join()

    # Clean up network configuration
    subprocess.run(['bash', 'clean-script.sh'])


def get_prio():
    """
    Checks Linux scheduler priorities of the server and iperf processes.
    Returns:
      (server_priority_ok, iperf_priority_ok)
    """
    try:
        output_server = subprocess.check_output(
            "ps -eLo comm,pri | grep server",
            shell=True,
            text=True
        )
        output_iperf = subprocess.check_output(
            "ps -eLo comm,pri | grep iperf",
            shell=True,
            text=True
        )

        result_server = "139" in output_server
        result_iperf = "139" not in output_iperf

        return result_server, result_iperf

    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve process priorities: {e}")
        return False, False


class WifiTest(unittest.TestCase):
    """
    Unittest checking if:
    - The server has real-time priority (139)
    - iperf does NOT have real-time priority
    """

    def test_prio(self):
        server_prio, iperf_prio = get_prio()
        self.assertTrue(server_prio)
        self.assertTrue(iperf_prio)


def main():
    """
    Main control logic:
    - Build Rust projects
    - Start iperf server
    - Execute test configurations sequentially
    - Track progress via status file
    """
    global all_results

    # Build Rust projects
    rust_build = ['cargo', 'build', '--release']
    subprocess.run(rust_build, cwd='/code/server_udp')
    subprocess.run(rust_build, cwd='/code/server')

    # Start iperf server
    iperf_process_container = []
    iperf_thread = threading.Thread(
        target=run_iperf_server,
        args=(iperf_process_container,)
    )
    iperf_thread.start()

    # Load test configurations
    with open("test_configuration", "r") as config:
        lines = config.readlines()

    # Resume execution using status file
    with open("status", "r") as status_file:
        n = int(status_file.read().strip())

    while n < len(lines):
        with open("status", "r") as status_file:
            n = int(status_file.read().strip())

        line = lines[n - 1].strip()
        process_line(line, n - 1)

        with open("status", "w", encoding="utf-8") as f:
            f.write(str(n + 1))

    # Stop iperf server
    if iperf_process_container:
        print("Stopping iperf server...")
        iperf_process = iperf_process_container[0]
        iperf_process.terminate()
        try:
            iperf_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            iperf_process.kill()

    iperf_thread.join()


if __name__ == '__main__':
    main()

# Reset status file after all tests
with open("status", "w", encoding="utf-8") as f:
    f.write("1")

# Write test results to output file
output_file = "test_results"
with open(output_file, "w", encoding="utf-8") as f:
    f.write("\nOverall test results:\n")

    for i, result in all_results:
        f.write(f"\nTest run {i}:\n")

        total_tests = result.testsRun
        failed = len(result.failures)
        errored = len(result.errors)
        successful = total_tests - failed - errored

        f.write(f"  Successful: {successful}\n")
        f.write(f"  Failures: {failed}\n")

        for test, traceback in result.failures:
            f.write(f"    Failure in {test.id()}:\n{traceback}\n")

        f.write(f"  Errors: {errored}\n")
        for test, traceback in result.errors:
            f.write(f"    Error in {test.id()}:\n{traceback}\n")
