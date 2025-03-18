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
*Ref 6: Wazuh is successfully running on DigitalOcean since March 17 at 21:56 UTC, with wazuh-manager.service active and essential components like wazuh-db, wazuh-analysisd, wazuh-remoted, wazuh-logcollector, and wazuh-modulesd initialized.*
