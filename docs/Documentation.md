# Network Defender:

Praetorian is a Python-based network defense application focused on detecting, logging, and responding to network scanning activities and OS fingerprinting attempts. This initial documentation covers the modules and functionalities implemented thus far.

---

## 1. Scan Detection Module

Implemented using `scapy`, the Scan Detection Module (`scan_detection.py`) captures network packets to identify scanning behaviors, specifically targeting TCP SYN packets commonly used for initiating connections.

### Detection Heuristics:

- Monitors TCP packets, specifically looking for SYN flags.
    
- Captures and flags multiple sequential or randomized port access attempts.
    

The module outputs immediate console alerts and integrates with the logging system to record potential scanning activity.

---

## 2. OS Fingerprinting Detection Module

The OS Fingerprinting Module (`os_fingerprinting.py`) analyzes captured TCP/IP packets for anomalies indicative of fingerprinting attempts:

### Current Heuristics:

- Checks TCP/IP packets for uncommon TTL (Time To Live) values outside typical OS defaults (64, 128, 255).
    
- Evaluates abnormal TCP window sizes (standard sizes: 5840, 8192, 65535).
    
- Identifies uncommon flag combinations like NULL scans (no flags) and FIN-only scans.
    

### Known Limitations:

- Current heuristics may flag legitimate network devices and benign traffic, leading to false positives.
    
- Further refinements and potentially advanced analytics (statistical analysis or machine learning) will be required for improved accuracy.
    

Alerts are logged with appropriate severity indicators, highlighting areas that need investigation.

---

## 3. Logging and Alerting Module

The logging module (`logging_module.py`) ensures consistent event recording from all detection modules.

### Supported Formats:

- **JSON:** Structured data logs ideal for automated processing and analysis.
    
- **Plaintext:** Simplified logs suitable for quick manual review and immediate response.
    

Future updates may introduce Markdown exports for documentation purposes.

Logs are stored locally, ensuring persistent records for review, analysis, and troubleshooting.

---

## 4. Interactive Terminal UI

The Rich-based UI Dashboard (`ui_dashboard.py`) provides real-time interactive monitoring:

### Dashboard Features:

- Real-time display of recent events, scans, and detected anomalies.
    
- Clear formatting with timestamps, severity levels, and event messages.
    
- Continuously refreshed UI to facilitate immediate incident response.
    

Future enhancements will integrate deeper interactions, module toggling, and visualization of firewall rules and active alerts.

---

## Upcoming Features and Modules

### Defensive Measures Module

- Planned integration for automated defensive responses.
    
- Will interface directly with firewall systems (Windows Firewall API, iptables, or similar).
    
- Configurable thresholds will dictate when automated actions trigger.
    

### Asynchronous Execution

- Modules will leverage Python's `asyncio` for concurrent and efficient handling of network events.
    

### Enhanced Alerting

- Planned real-time alert integrations, including email, Discord, or Slack notifications.
    

---

## Future Considerations

- **Heuristic Refinement:** Iterative testing and refinement of heuristic detection rules to reduce false positives and enhance reliability.
    
- **Maintenance:** Regular updates and heuristic adjustments will be necessary, driven by real-world testing and feedback.
    
- **Documentation Updates:** Continuous documentation of architectural decisions, heuristic adjustments, and module enhancements to support clarity and future maintenance.