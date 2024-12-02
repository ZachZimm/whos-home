import sys
import pyshark
from scapy.all import ARP, Ether, srp
import csv
import time
from datetime import datetime
import sqlite3
from fastapi import FastAPI
import uvicorn
import threading
from typing import Dict, List, Any

# Define database name
DB_NAME = 'connections.db'

# Initialize the device registry
device_registry = {}

# Dictionary to store currently connected devices
connected_devices = {}

# Load device registry
with open('device_registry.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        device_registry[row['MAC Address']] = {
            'device_name': row['Device Name'],
            'user': row['User']
        }

# Initialize device last seen dictionary
connection_log = {}
ip_mac_mapping = {}

# Initialize lock for connection_log
connection_log_lock = threading.Lock()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS connection_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def load_connection_log():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        SELECT mac_address, timestamp, status FROM connection_events ORDER BY timestamp
    ''')
    rows = c.fetchall()
    conn.close()

    log = {}
    for mac_address, timestamp_str, status in rows:
        timestamp = datetime.fromisoformat(timestamp_str)
        if mac_address not in log:
            log[mac_address] = []
        log[mac_address].append({
            'timestamp': timestamp,
            'status': status
        })
    return log

def arp_ping(ip, is_retry=False):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # return whether the IP is online
    responded = len(answered_list) > 0
    if not responded and not is_retry:
        # retry once
        return arp_ping(ip, is_retry=True)
    return responded

def log_device_activity(mac_address, action):
    device_info = device_registry.get(mac_address, {})
    user = device_info.get('user', 'Unknown')
    device_name = device_info.get('device_name', 'Unknown Device')
    ip_address = ip_mac_mapping.get(mac_address, 'Unknown IP')

    if device_name == "router":
        return
    if device_name == "think":  # this is the device running this program
        return

    status = 0 if action == 'Disconnected' else 1
    event = {
        'timestamp': datetime.now(),
        'status': status
    }

    with connection_log_lock:
        if mac_address not in connection_log:
            connection_log[mac_address] = []
        elif connection_log[mac_address][-1]['status'] == status:
            return
        connection_log[mac_address].append(event)

    # Write to sqlite database
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO connection_events (mac_address, timestamp, status) VALUES (?, ?, ?)
    ''', (mac_address, event['timestamp'].isoformat(), status))
    conn.commit()
    conn.close()

    # Also write to csv for easy access
    with open('device_log.csv', 'a', newline='') as csvfile:
        logwriter = csv.writer(csvfile)
        logwriter.writerow([
            event['timestamp'],
            mac_address,
            ip_address,
            device_name,
            user,
            action
        ])

def update_device_last_seen(mac_address):
    global connected_devices
    log_device_activity(mac_address, 'Connected')
    connected_devices[mac_address] = (time.time(), True)

def check_for_disconnections(timeout=300):
    global connected_devices
    for mac_address in list(connected_devices.keys()):
        ip_address = ip_mac_mapping.get(mac_address)
        if not ip_address:
            continue
        ping = arp_ping(ip_address)
        if not ping:
            log_device_activity(mac_address, 'Disconnected')
            connected_devices[mac_address] = (time.time(), False)
    return

def main():
    global connected_devices, ip_mac_mapping
    interface = 'wlp4s0'
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    capture = pyshark.LiveCapture(interface=interface)
    last_disconnect_check = time.time()
    for packet in capture.sniff_continuously():
        try:
            if 'DHCP' in packet or 'ARP' in packet:
                mac_address = packet.eth.src
                if 'DHCP' in packet:
                    if packet.dhcp.option_dhcp == '1':  # DHCP Discover
                        mac_address = packet.eth.src
                    elif packet.dhcp.option_dhcp == '2':  # DHCP Offer
                        mac_address = packet.eth.dst
                        ip_address = packet.ip.dst
                        ip_mac_mapping[mac_address] = ip_address
                if 'ARP' in packet:
                    mac_address = packet.arp.src_hw_mac
                    ip_address = packet.arp.src_proto_ipv4
                    ip_mac_mapping[mac_address] = ip_address
                if mac_address:
                    update_device_last_seen(mac_address)
            if time.time() - last_disconnect_check > 10:
                last_disconnect_check = time.time()
                check_for_disconnections()
        except AttributeError:
            continue

app = FastAPI()

@app.get('/connections')
def get_connections():
    with connection_log_lock:
        data = {}
        for mac_address, events in connection_log.items():
            data[mac_address] = []
            for event in events:
                data[mac_address].append({
                    'timestamp': event['timestamp'].isoformat(),
                    'status': event['status']
                })
    return data

@app.get('/devices')
def get_devices():
    return device_registry

if __name__ == '__main__':
    # Initialize database
    init_db()
    # Load connection_log from database
    connection_log = load_connection_log()

    # Start packet sniffing in a separate thread
    sniffing_thread = threading.Thread(target=main)
    sniffing_thread.daemon = True
    sniffing_thread.start()

    # Run FastAPI app
    uvicorn.run(app, host='0.0.0.0', port=1234)
