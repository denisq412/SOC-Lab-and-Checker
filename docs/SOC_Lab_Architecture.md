# 🏗️ Enterprise SOC Lab Architecture & Telemetry Pipeline

## 1. Environment Overview
The SOC laboratory was designed on VMware Workstation to replicate a segmented enterprise network with perimeter firewalling, network intrusion detection, Active Directory identity infrastructure, and centralized SIEM log management.

| Hostname / Role | IPv4 Address | Operating System | Key Services & Ports | Telemetry Shipped to SIEM |
| :--- | :--- | :--- | :--- | :--- |
| **`pfSense.mydomain.local`**<br>Perimeter Gateway & IDS | `172.16.50.1` | pfSense CE 2.7.2 (FreeBSD) | DNS (`:53`), NTP (`:123`), SNMP (`:161`), Snort IDS, Packet Filter | Syslog (`:5140`) $\rightarrow$ `.ds-logs-pfelk-firewall-*` & `.ds-logs-pfelk-snort-*` |
| **`soc`**<br>Central SIEM Server | `172.16.50.2` | Ubuntu Server / Elastic 8.15.2 | Kibana (`:5601`), Elasticsearch REST API (`:9200`), Logstash/Fleet | Generates `.internal.alerts-security.alerts-*` |
| **`DC.mydomain.local`**<br>Active Directory DC | `172.16.50.254` | Windows Server 2016 Datacenter | AD DS (`:88` Kerberos, `:389` LDAP, `:445` SMB, `:3389` RDP) | Elastic Agent / Filebeat / Winlogbeat 8.15.5 $\rightarrow$ `.ds-logs-system.security-default-*` |
| **`kali`**<br>Purple Team Simulator | `172.16.50.51` | Kali Linux | `nx220.sh`, Nmap, Hping3, Masscan, THC-Hydra | Local Audit Log (`/var/log/soc_checker.log`) + Live ES API Verifier |

---

## 2. Log Ingestion & Forwarder Architecture

### A. Windows Server 2016 Domain Controller (`172.16.50.254`)
* **Agent:** Elastic Agent / Filebeat / Winlogbeat (`v8.15.5`) paired with **Sysmon** (`detections/sysmonconfig-export.xml`).
* **Audited Event Channels:**
  * `Security` (`Event ID 4624` Logon Success, `Event ID 4625` Logon Failure, `Event ID 4672` Special Privileges, `Event ID 4768/4769/4771` Kerberos Authentication, `Event ID 5152/5156` Windows Filtering Platform).
  * `System` & `Application` event logs.
  * `Microsoft-Windows-Sysmon/Operational` (Process creation `Event ID 1`, Network connection `Event ID 3`, Registry modifications `Event ID 12/13`).

### B. pfSense Firewall & Snort Network IDS (`172.16.50.1`)
* **Firewall Packet Logging (`filterlog`):** Configured to log matched pass/block rules (specifically `Rule 86` on interface `em1`) and stream RFC 3164/5424 Syslog UDP payloads to the ELK Stack listener (`172.16.50.2:5140`).
* **Snort IDS Package:** Inspects ingress/egress LAN traffic on `em1`. Custom and emerging-threats rules detect anomalous ICMP types (`SID 1:9000000:0` & `SID 1:1000001:0`), TCP SYN floods (`stream5`), and rapid port sweeps (`sfportscan`).

### C. Elastic Stack SIEM (`172.16.50.2`)
* **Elasticsearch (`https://172.16.50.2:9200`):** Stores normalized ECS (Elastic Common Schema) documents across data streams:
  * `.ds-logs-system.security-default-*` (Windows AD Security Events)
  * `.ds-logs-pfelk-firewall-*` (pfSense `filterlog` events)
  * `.ds-logs-pfelk-snort-*` (Snort IDS alerts)
  * `.internal.alerts-security.alerts-*` (Kibana Security Detection Engine alerts)
* **Kibana Security (`http://172.16.50.2:5601`):** Runs scheduled detection rules every 5 minutes with a lookback window to correlate multi-host telemetry and generate high-severity incident alerts.
