import pyshark
import csv
import time
from datetime import datetime

# Load device registry
device_registry = {}

# Dictionary to store currently connected devices
# Currently unused, but it will eventually be managed and its state will be logged
connected_devices = {}

with open('device_registry.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        device_registry[row['MAC Address']] = {
            'device_name': row['Device Name'],
            'user': row['User']
        }

# Initialize device last seen dictionary
device_last_seen = {}

# Initialize IP to MAC mapping dictionary
ip_mac_mapping = {}


def log_device_activity(mac_address, action):
    device_info = device_registry.get(mac_address, {})
    user = device_info.get('user', 'Unknown')
    device_name = device_info.get('device_name', 'Unknown Device')
    ip_address = ip_mac_mapping.get(mac_address, 'Unknown IP')

    with open('device_log.csv', 'a', newline='') as csvfile:
        logwriter = csv.writer(csvfile)
        logwriter.writerow([
            datetime.now(),
            mac_address,
            ip_address,
            device_name,
            user,
            action
        ])

def update_device_last_seen(mac_address):
    if mac_address not in device_last_seen:
        log_device_activity(mac_address, 'Connected')
    device_last_seen[mac_address] = time.time()

def check_for_disconnections(timeout=300):
    return # TODO implement pinging routine
    current_time = time.time()
    for mac_address, last_seen in list(device_last_seen.items()):
        if current_time - last_seen > timeout:
            log_device_activity(mac_address, 'Disconnected')
            del device_last_seen[mac_address]

capture = pyshark.LiveCapture(interface='wlp4s0')

for packet in capture.sniff_continuously():
    try:
        if 'DHCP' in packet or 'ARP' in packet:
            # mac_address = packet.eth.src
            # print(packet.eth)
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
        check_for_disconnections()
    except AttributeError:
        continue
