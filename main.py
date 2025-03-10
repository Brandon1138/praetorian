# main.py
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Import detection and UI modules from the modules folder.
from modules import scan_detection, os_fingerprinting, ui, firewall_automation

async def run_scan_detection(loop):
    # Run the scan detection in an executor since scapy.sniff is blocking.
    await loop.run_in_executor(None, scan_detection.start_sniffing)

async def run_os_fingerprinting(loop):
    # Similarly, run OS fingerprinting detection in an executor.
    await loop.run_in_executor(None, os_fingerprinting.start_os_fingerprinting)

async def run_ui(loop):
    # Run the Rich-based UI dashboard.
    await loop.run_in_executor(None, ui.main)

async def run_firewall_monitoring(loop):
    # Placeholder for firewall automation tasks.
    # Here you could implement periodic checks or trigger actions based on aggregated alerts.
    # For now, this will just be an idle loop.
    while True:
        # In a full implementation, check logs or thresholds and call firewall_automation.block_ip(ip)
        await asyncio.sleep(10)

async def main():
    loop = asyncio.get_event_loop()
    # Using ThreadPoolExecutor for blocking functions
    with ThreadPoolExecutor() as executor:
        tasks = [
            asyncio.create_task(run_scan_detection(loop)),
            asyncio.create_task(run_os_fingerprinting(loop)),
            asyncio.create_task(run_ui(loop)),
            asyncio.create_task(run_firewall_monitoring(loop)),
        ]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down Praetorian...")
