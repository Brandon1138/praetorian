# modules/firewall_automation.py
import subprocess
import platform

def block_ip(ip_address):
    """
    Blocks the given IP address using system-specific firewall commands.
    For Linux, it uses iptables; for Windows, it uses netsh.
    """
    os_type = platform.system()
    if os_type == "Linux":
        # For Linux systems, using iptables. Adjust as needed for ufw or other tools.
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    elif os_type == "Windows":
        # For Windows systems, using netsh.
        command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
    else:
        print("Firewall automation not supported on this OS.")
        return

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"[Firewall Automation] Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"[Firewall Automation] Failed to block IP {ip_address}: {e}")

if __name__ == "__main__":
    # Example usage (for testing purposes only):
    test_ip = "192.0.2.1"  # Replace with a test IP as needed.
    block_ip(test_ip)
