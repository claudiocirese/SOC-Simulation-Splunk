# SOC Simulator with Splunk

## Introduction
This project is a lightweight SOC (Security Operations Center) simulation,
designed to demonstrate skills in SIEM/Splunk and cybersecurity.
It generates logs with fake IPs and a malicious IP to mimic scanning and
brute force attempts. 

**Purpose**
- Show how to generate realistic logs for training.
- Build a Splunk dashboard with multiple panels.
- Implement scheduled alerts for security scenarios.

It includes:
- A Python script that generates fake logs (Apache Access, Apache Error, Firewall, Windows).
- A Splunk dashboard showing various panels (HTTP scanning, brute force attempts, etc.).
- Several Splunk alerts triggered by abnormal behaviors.


## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [How to Use](#how-to-use)
   1. [Sample queries for dashboard panels](#sample-queries-for-dashboard-panels)
   2. [Sample queries for alerts](#sample-queries-for-alerts)
5. [Analysis and Correlation](#analysis-and-correlation)
6. [Screenshots](#screenshots)
7. [Notes](#notes)
8. [License](#license)
9. [Author](#author)


## Features
- **generate_logs.py** produces:
  - `apache_access.txt`
  - `apache_error.txt`
  - `firewall_logs.txt`
  - `windows_logs.txt`
- **Splunk Dashboard** includes:
  -  HTTP Status Code Distribution
  -  HTTP Activity Over Time
  -  Top Requesting IPs
  -  Error Severity Over Time
  -  Firewall Activity
  -  Windows Event ID Distribution
  -  Suspected HTTP Scanning (404/500)
  -  Windows Brute Force Attempts (4625)
  -  Geo Distribution of Traffic
- **Alerts**:
  -  HTTP Scanning (404 Overload)
  -  High Error Rate
  -  INCIDENT_IP Scanning
  -  Windows Brute Force


## Requirements
- Python 3 to run the script `generate_logs.py`.
- A Splunk environment (Splunk Enterprise / Free) to ingest data and view the dashboards.


## How to Use

### 1) Clone this repository or download it
```bash
git clone https://github.com/claudiocirese/SOC-Simulation-Splunk.git
cd  SOC-Simulation-Splunk
```

### 2) Run the script to generate the logs
```bash
python generate_logs.py
```
This creates the following logs:
- `apache_access.txt`
- `apache_error.txt`
- `firewall_logs.txt`
- `windows_logs.txt`

### 3) Add data
1. In Splunk, go to “Add Data” → “Upload” and select `apache_access.txt`.
   - sourcetype = `apache_access`
   - index = `<your_index>`
2. Repeat for `apache_error.txt` (apache_error), `firewall_logs.txt` (firewall_log), 
`windows_logs.txt`(win_event_log).

### 4) Build the dashboard
- Create a new dashboard in Splunk (for example, "SOC_Dashboard").
- Save searches as panels. Examples include HTTP Status, HTTP Activity Over Time, and so on.
### Sample queries for dashboard panels
- **HTTP Status Code Distribution**
```spl 
index=<your_index> sourcetype=apache_access
| stats count AS Requests by status
| sort -Requests
``` 
- **HTTP Activity Over Time**
```spl 
index=<your_index> sourcetype=apache_access
| timechart count by status
```
- **Top Requesting IPs**
```spl
index=<your_index> sourcetype=apache_access
| stats count AS Hits by clientip
| sort -Hits
| head 4
```
- **Error Severity Over Time**
```spl
index=<your_index> sourcetype=apache_error
| timechart count AS Events by severity
```
- **Suspected HTTP Scanning (404/500)**
```spl
index=<your_index> sourcetype=apache_access (status=404 OR status=500)
| stats count AS ErrorHits by clientip
| sort -ErrorHits
| head 10
```
- **Windows Event ID**
```spl 
index=<your_index> sourcetype=win_event_log
| stats count AS "Events" by ID
| sort -Events
```
- **Firewall Activity**
```spl
index=<your_index> sourcetype=firewall_log
| stats count AS "Count" by act
| sort -Count
```
- **Windows Bruteforce Attempts (4625)**
```spl
index=<your_index> sourcetype=win_event_log ID=4625
| stats count AS FailCount by clientip
| sort -FailCount
| head 10
```
- **Geo Distribution of Traffic**
```spl
index=<your_index> (sourcetype=apache_access OR sourcetype=apache_error OR sourcetype=firewall_log OR sourcetype=win_event_log)
| iplocation clientip
| geostats latfield=lat longfield=lon count
```

### 5) Create Alerts
From “Search & Reporting”, save researches as “Scheduled Alert” (see queries), for 
scenarios like brute force attempts, 404 errors, or a specific INCIDENT_IP generating
too many errors.
Advised thresholds: > 10 404 errors, > 5 login fail...
### Sample queries for alerts
- **HTTP Scanning (404 Overload)**
```spl
index=<your_index> sourcetype=apache_access (status=404 OR status=500)
| stats count AS ErrorHits by clientip
| where ErrorHits > 10
```
- **High Error Rate**
```spl
index=<your_index> sourcetype=apache_access
| eval isError=if(status>=400,1,0)
| stats count(eval(isError=1)) AS Errors, count AS Total
| eval ErrorRate=round((Errors*100)/Total,2)
| where ErrorRate > 10
```
- **INCIDENT_IP Scanning**
```spl
index=<your_index> sourcetype=apache_access clientip=9.9.9.9 (status=404 OR status=500)
| stats count AS ErrorHits
| where ErrorHits > 20
```
- **Windows Brute Force**
```spl
index=<your_index> sourcetype=win_event_log ID=4625
| stats count AS FailCount by clientip
| where FailCount > 5
```
### Handling Alerts

Below are recommended actions when an alert triggers:

1. **HTTP Scanning (404 Overload)**  
   - Investigate the source IP for possible scanning.
   - Check if it's a known vulnerability scanner or malicious source.
   - Potentially block the IP at firewall if malicious.

2. **High Error Rate**  
   - Inspect server resources and logs for 404/500 spikes or high system load.
   - Could be an attack or a performance issue.

3. **INCIDENT_IP Scanning**  
   - If the IP 9.9.9.9 triggers too many errors, treat it as a priority threat.
   - Escalate to the security team for immediate action (block or in-depth analysis).

4. **Windows Brute Force**  
   - Check repeated failed logon attempts (ID=4625).
   - Possibly lock the account or block the IP.
   - Investigate if user credentials are compromised.
  
## Analysis and Correlation

In a real SOC, different logs are often correlated to see if there's a multi-stage attack happening. Although the logs here are generated by a script, the dashboard panels can illustrate a hypothetical scenario:

1. **Suspected HTTP Scanning (404/500)**  
   - From the dashboard screenshot, `9.9.9.9` shows **173** error hits, far exceeding other IPs (e.g. 48 for `8.8.8.8`, 42 for `192.168.1.1`, etc.).  
   - Such a high count of 404/500 could indicate **extensive scanning** or fuzzing of the web application.

2. **Windows Brute Force Attempts (4625)**  
   - The same IP, `9.9.9.9`, also appears at the top of the Windows Brute Force panel with multiple failed logon attempts.  
   - Correlating these two panels suggests a two-phase attack: scanning the web endpoints, followed by brute force on Windows credentials.

3. **Firewall Activity**  
   - If you see repeated `DROP` or `REJECT` actions for the same IP in `firewall_logs.txt`, that indicates your firewall is actively blocking or alerting on suspicious traffic.

4. **High Error Rate**  
   - Whenever the total 4xx/5xx ratio surpasses 10%, an alert is triggered. This might coincide with the same IP (`9.9.9.9`) generating numerous 404 errors, pointing to either a denial-of-service attempt or malicious scanning.

5. **INCIDENT_IP**  
   - In the script, `INCIDENT_IP` is given extra “attack-like” behavior. Whenever it appears across multiple logs (Apache, Windows, Firewall), it can be concluded that it’s involved in a broader intrusion attempt.

By correlating these logs, one can build a lightweight storyline of how an attacker might probe an environment at multiple layers. Although these logs are synthetic, the methodology remains the same as in a real SOC:
- **Identify** a suspicious IP from any log source.
- **Check** if the same IP shows malicious activity in other logs.
- **Act** (block, escalate, investigate) once correlation confirms an attack pattern.


## Screenshots
The following screenshots show parts of the simulation:
- **Dashboard**  
  ![Dashboard 1](screenshots/dashboard1.JPG)
  ![Dashboard 2](screenshots/dashboard2.JPG)
  ![Dashboard 3](screenshots/dashboard3.JPG)
- **Alerts**  
  ![Alerts 1](screenshots/alert1.JPG)
  ![Alerts 2](screenshots/alert2.JPG)
  ![Alerts 3](screenshots/alert3.JPG)
  ![Alerts 4](screenshots/alert4.JPG)


## Notes
- If you do not load more logs in the future, the dataset remains static, but is sufficient 
for demonstration.
- If you want to see alerts actually triggered, you can re-generate logs with fresh timestamps.
- You can adjust thresholds both in the Python script (distribution of errors,
incident IP) and the Splunk alerts (number of errors or failed logins).


## License
This project is released under the [MIT License](./LICENSE).

## Author
Created by Claudio Cirese, (C) 2024.  
For any inquiries, contact <claudiocirese1@gmail.com>  
[LinkedIn](https://www.linkedin.com/in/claudio-cirese-9792472bb)
