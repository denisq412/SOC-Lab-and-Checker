# 🎯 SOC Analyst Detection Playbook & Hunting Queries

This playbook documents the exact **MITRE ATT&CK mappings**, **Defender Telemetry Sources**, **Kibana KQL queries**, and **Splunk SPL queries** generated and verified by `nx220.sh`.

---

## 1. Nmap Stealth SYN & Service Enumeration (`Attack [1]`)
* **MITRE ATT&CK:** `TA0043` Reconnaissance / `T1046` Network Service Discovery
* **Simulation Command:**
  ```bash
  nmap -sS -sV -Pn -T4 --max-retries 1 --host-timeout 25s -p 21,22,53,80,88,135,139,389,443,445,3389,5601,8080,9200 <TARGET_IP>
  ```
* **Telemetry Sources:** pfSense `filterlog` (`Rule 86` / Block Rules), Zeek `conn.log` (`S0`/`REJ`), Windows Filtering Platform (`Event ID 5152` / `5156`).
* **Kibana KQL Query:**
  ```kql
  source.ip : "172.16.50.51" and destination.ip : "<TARGET_IP>" and (network.protocol : "tcp" or event.dataset : "pfelk.firewall")
  ```
* **Splunk SPL Query:**
  ```spl
  index=* src_ip="172.16.50.51" dest_ip="<TARGET_IP>" | stats dc(dest_port) as unique_ports by src_ip, dest_ip | where unique_ports > 10
  ```

---

## 2. Hping3 TCP SYN Flood / DoS Telemetry Probe (`Attack [2]`)
* **MITRE ATT&CK:** `TA0040` Impact / `T1498.001` Direct Network Flood
* **Simulation Command:**
  ```bash
  hping3 -S -p 5601 -w 64 -i u10000 -c 20 <TARGET_IP>
  ```
* **Telemetry Sources:** pfSense `filterlog`, Snort IDS (`stream5` / SYN flood threshold), Suricata `fast.log`.
* **Kibana KQL Query:**
  ```kql
  source.ip : "172.16.50.51" and destination.ip : "<TARGET_IP>" and (pf.flags : "S" or event.dataset : "pfelk.firewall")
  ```
* **Splunk SPL Query:**
  ```spl
  index=firewall src_ip="172.16.50.51" dest_ip="<TARGET_IP>" tcp_flag="S" | timechart span=10s count by src_ip
  ```

---

## 3. Masscan Rapid Multi-Port Administrative Sweep (`Attack [3]`)
* **MITRE ATT&CK:** `TA0043` Reconnaissance / `T1046` Network Service Discovery
* **Simulation Command:**
  ```bash
  masscan <TARGET_IP> -p21,22,23,25,53,80,88,110,135,139,389,443,445,3389,5601,8080,9200 --rate 100 --wait 2
  ```
* **Telemetry Sources:** pfSense `filterlog` (`.ds-logs-pfelk-firewall-*`), Network IDS Portscan Preprocessor (`sfportscan`).
* **Kibana KQL Query:**
  ```kql
  source.ip : "172.16.50.51" and destination.port : (22 or 80 or 88 or 135 or 389 or 445 or 3389 or 5601 or 9200)
  ```
* **Splunk SPL Query:**
  ```spl
  index=netflow OR index=firewall src_ip="172.16.50.51" dest_ip="<TARGET_IP>" | stats values(dest_port) count by src_ip, dest_ip
  ```

---

## 4. Hydra Authentication Brute-Force (`Attack [4]`)
* **MITRE ATT&CK:** `TA0006` Credential Access / `T1110.001` Password Guessing
* **Simulation Command:**
  ```bash
  hydra -l "soc_test_user" -P <3-password-list> -t 1 -W 1 -f <TARGET_IP> smb
  ```
* **Telemetry Sources:** Windows Security Auditing **Event ID 4625** (`Status: 0xC000006D`, `SubStatus: 0xC0000064`), **Kibana High-Severity Alert Rule `bf`** (`Threshold >= 3` failed logons in `5m`, Risk Score `73`), Linux `/var/log/auth.log`.
* **Kibana KQL Query:**
  ```kql
  event.code : "4625" and source.ip : "172.16.50.51" and user.name : "soc_test_user"
  ```
* **Splunk SPL Query:**
  ```spl
  index=wineventlog EventCode=4625 Source_Network_Address="172.16.50.51" TargetUserName="soc_test_user" | stats count by ComputerName, TargetUserName, Source_Network_Address
  ```

---

## 5. ICMP & UDP Perimeter IDS Signature Trigger (`Attack [5]`)
* **MITRE ATT&CK:** `TA0007` Discovery / `T1018` Remote System Discovery
* **Simulation Command:**
  ```bash
  hping3 --icmp -c 10 --fast <TARGET_IP>
  nmap -sU -Pn -T4 --max-retries 1 -p 53,123,137,161 <TARGET_IP>
  ```
* **Telemetry Sources:** Snort IDS (`[1:9000000:0] ICMP Detected` / `[1:1000001:0] Ping detected`), pfSense `filterlog` Rule 86 (UDP).
* **Kibana KQL Query:**
  ```kql
  source.ip : "172.16.50.51" and (event.dataset : "pfelk.snort" or (event.dataset : "pfelk.firewall" and network.transport : ("icmp" or "udp")))
  ```
* **Splunk SPL Query:**
  ```spl
  index=pfelk (sourcetype=snort OR sourcetype=pf_firewall) src_ip="172.16.50.51" | table _time, host, src_ip, dest_ip, proto, signature
  ```
