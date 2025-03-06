# ADR-001: OS Fingerprinting and Scan Detection Heuristics

## Status:

Accepted

## Context:

The Praetorian network defense system needs reliable detection of network scans and OS fingerprinting attempts. Initial heuristic approaches for OS fingerprinting detection, focusing on analyzing unusual TTL values, TCP window sizes, and odd TCP flag combinations, have been implemented. However, during preliminary testing, these heuristics showed limitations and triggered false positives, particularly flagging legitimate network devices or the host machine itself.

## Decision:

- Continue using current heuristic-based approaches with known typical TTL values (64, 128, 255) and TCP window sizes (5840, 8192, 65535).
    
- Explicitly document the heuristic’s potential for false positives, particularly involving standard devices or network traffic.
    
- Plan iterative refinement cycles to develop more nuanced heuristics, possibly integrating statistical analysis or machine learning methods in future versions to improve accuracy.
    

## Consequences:

- Immediate functionality for detecting clear and overt OS fingerprinting attempts.
    
- Risk of false positives, leading to possible alert fatigue or overlooking legitimate alerts if excessive benign traffic is flagged.
    
- Requirement for further development and testing of refined heuristic or advanced detection methods to mitigate false positives and enhance overall reliability.