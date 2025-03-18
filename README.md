# SOC Automation Lab

## Objective
I built this SOC Automation Lab to develop and test automated security workflows that enhance threat detection, log analysis, and incident response. Using SIEM, SOAR, and custom scripts, I aim to reduce manual workload, improve response times, and minimize false positives. This project focuses on real-world SOC challenges, optimizing processes to strengthen security operations.

### Skills Learned
- SIEM Configuration & Tuning – Optimizing alerts, log ingestion, and correlation rules
- SOAR Automation – Implementing automated incident response playbooks
- Threat Intelligence Integration – Enriching alerts with external threat feeds
- Log Analysis & Correlation – Identifying patterns across multiple data sources
- Automated Alert Triage – Reducing false positives and prioritizing real threats
- Incident Response Automation – Enhancing remediation with scripted workflows
- Threat Hunting – Leveraging automation for anomaly detection and IOC analysis
- Scripting (Python, PowerShell, Bash) – Automating security tasks and log parsing
- API Integration – Connecting security tools for data exchange and workflow automation
- Reporting & Metrics – Automating SOC performance tracking and threat trends analysis

### Tools Used
- SIEM – Wazuh (log collection, analysis, and threat detection)
- SOAR & Case Management – TheHive/Shuffle (incident response and investigation workflows)
- Cloud Infrastructure – DigitalOcean (hosting and managing lab environments)
- Threat Intelligence – VirusTotal (integrating threat feeds for enriched detection)
- Scripting & Automation – Python, Bash (automating security tasks and log parsing)
- Log Management – Wazuh (monitoring system logs and security events)
- API Integration – Connecting Wazuh, TheHive, and threat intelligence sources for automation

## Steps
![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/9185de0c50ddae393dfe57ca85fe24b19b09d496/HOME%20LAB%20DIAGRAM.jpg)
*Ref 1: Automation Diagram*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/sysmon%20installed%20screenshot.png?raw=true)
*Ref 2: Sysmon successfully installed and running as a service, with its executables and configuration files in place*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/wazuh%20dashboard%20screenshot.png?raw=true)
*Ref 3: Wazuh successfully installated with a fully operational security events dashboard, actively monitoring and analyzing alerts* 

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/firewall%20digital%20ocean%20config.png?raw=true)
*Ref 4: Firewall rules on DigitalOcean configured for Wazuh and TheHive, allowing inbound traffic from a specific IP and enabling necessary outbound communication*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/thehive%20config%20services%20screensht.png?raw=true)
*Ref 5: TheHive is successfully installed and running on DigitalOcean since Mar 15th 2025 @ 16:01 UTC, with Elasticsearch and Cassandra services also active*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/wazuh%20configs%20screenshot.png?raw=true)
*Ref 6: Wazuh is successfully running on DigitalOcean since Mar 17th @ 21:56 UTC, with wazuh-manager.service active and essential components like wazuh-db, wazuh-analysisd, wazuh-remoted, wazuh-logcollector, and wazuh-modulesd initialized*

![Image alt](https://github.com/user-attachments/assets/6694a94b-fee9-4550-a542-b3cd7df9a024)
*Ref 7: I configured OSSEC to analyze Sysmon logs, enhancing Windows 10 telemetry for detecting threats like Mimikatz. This enables Wazuh to alert on suspicious activity using detailed system event tracking*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/sysmon%20events%20within%20wazuh%20.png?raw=true)
*Ref 8: Shows Sysmon events are successfully populating in Wazuh, showing logs from agent "Elijah" with alerts for process injection and potential malware execution. The rule IDs, severity levels, and timestamps indicate active monitoring, verifying that Wazuh is detecting and processing Sysmon logs effectively*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/mimikatz%20detection.png?raw=true)
*Ref 9: This shows Wazuh is successfully detecting Mimikatz, showing an alert with rule ID 100002, severity 15, and the description "Mimikatz Usage Detected." Wazuh identifies Mimikatz usage based on behavioral patterns rather than just the file name, ensuring detection even if the executable is renamed*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/wazuh%20filebeat%20and%20archives.png?raw=true)
*Ref 10: Wazuh is configured in Filebeat to archive and alert on all events, as shown in the terminal with enabled modules (alerts, archives) and in the Wazuh dashboard displaying various security logs* 

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/shuffle%20workflow%201.png?raw=true)
*Ref 11: First part of my Shuffle workflow integrating Wazuh, where Wazuh alerts are received via a webhook for automated processing*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/shuffle%20wazuh%20integration%20.png?raw=true)
*Ref 12: Wazuh is successfully integrated with Shuffle. The Wazuh config (right) sends alerts via webhook, and Shuffle (left) displays a detected Mimikatz usage alert, verifying proper event forwarding*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/parsed%20hash.png?raw=true)
*Ref 13: Shuffle successfully extracted the Mimikatz hash using regex. The workflow applied the regex pattern SHA256=([A-Fa-f0-9]{64}) to the input data and correctly captured the SHA256 hash, as shown in the output*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/shuffle%20workflow%202.png?raw=true)
*Ref 14: I integrated VirusTotal into the workflow for threat intelligence by enriching Wazuh alert hashes, automating security insights*

![Image alt](https://github.com/eliarns/SOC-Automation-Lab/blob/main/virustotal%20success.png?raw=true)
*Ref 15: VirusTotal enriched the detected hash successfully, identifying it as Mimikatz with 65/73 detections. This was confirmed in Shuffle’s VirusTotal response implemented within my created workflow and on VirusTotal’s website*

![Image alt](


