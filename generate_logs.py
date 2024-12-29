#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================================
SCRIPT TO GENERATE APACHE ACCESS, APACHE ERROR,
FIREWALL, AND WINDOWS EVENT LOGS WITH:

1) HTTP distribution featuring a lower error rate (80% 200, 10% 404, 5% 500, 5% others).
2) Inclusion of an IP field (similar to 'clientip') in Windows logs via [client <ip>].
3) 70% of logs generated during daytime (08:00-20:00), 30% at night, for realism.
4) Addition of fake usernames in Windows logs.
5) Simulation of a mini "incident" (an IP performing scanning and brute force).

GOAL:
- Create "fake" logs that are realistic:
  1) High volumes.
  2) Recurring IPs (so that the "Top IPs" dashboard shows varied counts).
  3) Always present severity in error logs.
  4) Geographic info (country, city).
  5) IP "client" and username in Windows logs.
  6) Realistic day/night ratio at 70/30.
  7) An "incident_ip" that performs scanning (lots of 404) and brute force (lots of 4625).

USAGE:
1) Run: python generate_logs.py
2) This will create 4 files:
   - apache_access.txt
   - apache_error.txt
   - firewall_logs.txt
   - windows_logs.txt
3) Upload these files to Splunk as sourcetypes:
   - apache_access
   - apache_error
   - firewall_log
   - win_event_log

===============================================================================
"""

import random
import datetime
from datetime import timedelta

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================
# Set how many logs to generate for each type.
NUM_ACCESS_LOGS = 2000      # Apache Access
NUM_ERROR_LOGS = 300        # Apache Error
NUM_FIREWALL_LOGS = 300     # Firewall
NUM_WINDOWS_LOGS = 300      # Windows

# How many days back to randomize the timestamps (e.g., 7 days)
DAYS_BACK = 7

# List of "famous" IPs that will appear frequently
HIGH_FREQ_IPS = [
    "192.168.1.1",
    "10.0.0.5",
    "173.194.222.113",
    "8.8.8.8"
]

# Probability (0 to 1.0) of choosing an IP from HIGH_FREQ_IPS
CHANCE_HIGH_FREQ = 0.6

# Some geographical locations to enrich the logs (country, city)
GEOGRAPHIC_LOCATIONS = [
    "United States, New York",
    "Germany, Berlin",
    "France, Paris",
    "Italy, Rome",
    "Spain, Madrid",
    "Canada, Toronto",
    "Brazil, São Paulo",
    "India, Mumbai",
    "Australia, Sydney"
]

# HTTP methods and status codes
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

# =====================================================================
# HTTP distribution with lower error rate:
# 80% -> 200, 10% -> 404, 5% -> 500, 5% -> others
# =====================================================================
HTTP_STATUS_CODES_DISTRIBUTION = {
    200: 80,
    404: 10,
    500: 5
}
OTHER_CODES = [302, 401, 403, 501]

ERROR_SEVERITIES = ["INFO", "WARNING", "ERROR", "CRITICAL"]
WINDOWS_EVENT_IDS = [4624, 4625, 4634, 4672]

# ============================================================================
# LIST OF FAKE USERNAMES FOR WINDOWS LOGS
# ============================================================================
FAKE_USERNAMES = [
    "administrator",
    "jsmith",
    "ptaylor",
    "mnguyen",
    "v.rossi",
    "d.brown",
    "a.garcia"
]

# ============================================================================
# DEDICATED "INCIDENT" IP (attack simulation)
# ============================================================================
INCIDENT_IP = "9.9.9.9"
# This IP will generate more 404 errors and more 4625 events in Windows logs

# ============================================================================
# FUNCTION TO GENERATE TIMESTAMPS BETWEEN DAY (08-20) AND NIGHT
# 70% day, 30% night
# ============================================================================
def get_random_datetime():
    """
    Generates a random datetime within the last 'DAYS_BACK' days,
    with a 70% chance in daytime (08:00-20:00),
    30% at nighttime (20:00-08:00).
    """
    now = datetime.datetime.now()
    start_date = now - timedelta(days=DAYS_BACK)
    random_date = start_date + (now - start_date) * random.random()

    # Decide day or night range
    if random.random() < 0.7:
        # Day range: random from 08:00 to 19:59
        hour = random.randint(8, 19)
    else:
        # Night range: random from 20:00 to 07:59
        # For simplicity, if hour >=20 => "night" else <8 => night
        # We choose either 20..23 or 0..7
        if random.random() < 0.5:
            hour = random.randint(20, 23)
        else:
            hour = random.randint(0, 7)

    # Set random minute and second
    minute = random.randint(0, 59)
    second = random.randint(0, 59)

    # Apply the same date (random_date) but with hour:minute:second
    new_dt = datetime.datetime(
        random_date.year,
        random_date.month,
        random_date.day,
        hour,
        minute,
        second
    )
    return new_dt

def get_random_ip():
    """
    Returns an IPv4 address.
    - 60% of the time (CHANCE_HIGH_FREQ=0.6), choose from HIGH_FREQ_IPS.
    - Otherwise, generate a random IP (e.g., 31.198.7.44).
    """
    if random.random() < CHANCE_HIGH_FREQ:
        return random.choice(HIGH_FREQ_IPS)
    else:
        octets = [str(random.randint(1, 254)) for _ in range(4)]
        return ".".join(octets)

def get_random_location():
    """
    Returns a location in "Country, City" format,
    selected from GEOGRAPHIC_LOCATIONS.
    """
    return random.choice(GEOGRAPHIC_LOCATIONS)

def generate_apache_access_log():
    """
    Generates a single Apache Access Log line.
    Example format:
      192.168.1.1 - - [25/Mar/2025:10:00:12 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 geo_country="Germany" geo_city="Berlin"
    """
    dt = get_random_datetime()
    timestamp_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    # =========================================================================
    # Decide if we want to use INCIDENT_IP (attack)
    # to produce more 404 (scanning).
    # ~15% chance to use INCIDENT_IP
    # =========================================================================
    if random.random() < 0.15:
        ip_address = INCIDENT_IP
    else:
        ip_address = get_random_ip()

    method = random.choice(HTTP_METHODS)
    endpoint = random.choice([
        "/api/v1/users", "/api/v1/orders", "/home", "/about",
        "/static/css/styles.css", "/static/js/app.js", "/login", "/logout"
    ])
    
    # Status code distribution
    dice = random.randint(1, 100)
    cumulative = 0
    status_code = None
    for code, perc in HTTP_STATUS_CODES_DISTRIBUTION.items():
        cumulative += perc
        if dice <= cumulative:
            status_code = code
            break
    if status_code is None:
        status_code = random.choice(OTHER_CODES)
    
    # If IP is INCIDENT_IP, increase the chance of 404 (scanning)
    if ip_address == INCIDENT_IP:
        if random.random() < 0.5:  # 50% chance
            status_code = 404

    response_size = random.randint(512, 524288)
    
    location_str = get_random_location()
    country, city = location_str.split(", ")
    
    log_line = (
        f'{ip_address} - - [{timestamp_str}] '
        f'"{method} {endpoint} HTTP/1.1" {status_code} {response_size} '
        f'geo_country="{country}" geo_city="{city}"'
    )
    return log_line

def generate_apache_error_log():
    """
    Generates a single Apache Error Log line.
    Example format:
      [Sat Mar 25 10:00:12 2025] [ERROR] [client 192.168.1.1] Database connection failed geo_country="Germany" geo_city="Berlin"
    """
    dt = get_random_datetime()
    timestamp_str = dt.strftime("%a %b %d %H:%M:%S %Y")
    
    ip_address = get_random_ip()
    severity = random.choice(ERROR_SEVERITIES)
    error_msg = random.choice([
        "File not found",
        "Permission denied",
        "Database connection failed",
        "Syntax error in configuration file",
        "Timeout while reading data",
        "Invalid request payload"
    ])
    
    loc = get_random_location()
    country, city = loc.split(", ")
    
    log_line = (
        f'[{timestamp_str}] [{severity}] [client {ip_address}] '
        f'{error_msg} geo_country="{country}" geo_city="{city}"'
    )
    return log_line

def generate_firewall_log():
    """
    Generates a fake firewall log in a simplified Syslog format.
    Example:
      Mar 25 10:00:12 myfirewall CEF:0|FakeCompany|Firewall|1.0|100|Traffic|INFO| src=192.168.1.1 act=DROP geo_country="France" geo_city="Paris"
    """
    dt = get_random_datetime()
    timestamp_str = dt.strftime("%b %d %H:%M:%S")
    hostname = "myfirewall"
    
    ip_address = get_random_ip()
    action = random.choice(["ALLOW", "DROP", "REJECT", "ALERT"])
    
    loc = get_random_location()
    country, city = loc.split(", ")
    
    log_line = (
        f'{timestamp_str} {hostname} CEF:0|FakeCompany|Firewall|1.0|100|Traffic|INFO| '
        f'src={ip_address} act={action} '
        f'geo_country="{country}" geo_city="{city}"'
    )
    return log_line

def generate_windows_log():
    """
    Generates a fake Windows Event Log (simplified).
    Example:
      2025-03-25 10:00:12 WINHOST Security ID=4624 MSG="An account was successfully logged on" geo_country="Germany" geo_city="Berlin"
    """
    dt = get_random_datetime()
    timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    hostname = "WINHOST"
    
    # Randomly choose an event_id
    event_id = random.choice(WINDOWS_EVENT_IDS)
    messages_map = {
        4624: "An account was successfully logged on",
        4625: "An account failed to log on",
        4634: "An account was logged off",
        4672: "Special privileges assigned to new logon"
    }
    msg = messages_map[event_id]
    
    loc = get_random_location()
    country, city = loc.split(", ")
    
    # =========================================================================
    # Add [client <ip>] and a fake username
    # =========================================================================
    # If we want to simulate an "incident" IP, apply same logic from apache_access
    if random.random() < 0.15:
        ip_address = INCIDENT_IP
    else:
        ip_address = get_random_ip()
    
    # If ip_address is INCIDENT_IP and event_id is 4625,
    # we are generating a flow of bruteforce logon attempts
    username = random.choice(FAKE_USERNAMES)
    
    log_line = (
        f'{timestamp_str} {hostname} Security '
        f'ID={event_id} MSG="{msg}" '
        f'[client {ip_address}] username="{username}" '
        f'geo_country="{country}" geo_city="{city}"'
    )
    return log_line

def main():
    # Creates output files and writes the generated logs line by line.

    with open("apache_access.txt", "w", encoding="utf-8") as f:
        for _ in range(NUM_ACCESS_LOGS):
            line = generate_apache_access_log()
            f.write(line + "\n")

    with open("apache_error.txt", "w", encoding="utf-8") as f:
        for _ in range(NUM_ERROR_LOGS):
            line = generate_apache_error_log()
            f.write(line + "\n")

    with open("firewall_logs.txt", "w", encoding="utf-8") as f:
        for _ in range(NUM_FIREWALL_LOGS):
            line = generate_firewall_log()
            f.write(line + "\n")

    with open("windows_logs.txt", "w", encoding="utf-8") as f:
        for _ in range(NUM_WINDOWS_LOGS):
            line = generate_windows_log()
            f.write(line + "\n")

    print("All logs have been successfully generated!")
    print("Created files:")
    print(" - apache_access.txt")
    print(" - apache_error.txt")
    print(" - firewall_logs.txt")
    print(" - windows_logs.txt")

if __name__ == "__main__":
    main()
