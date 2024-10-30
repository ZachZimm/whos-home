import pyshark
from scapy.all import ARP, Ether, srp
import csv
import time
from datetime import datetime

# Load device registry
device_registry = {}

# Dictionary to store currently connected devices
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
    if device_name == "think": # this is the device running this program, I'll implementent better self-identification later
        return

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
    log_device_activity(mac_address, 'Connected')
    connected_devices[mac_address] = (time.time(), True)
    device_last_seen[mac_address] = time.time()

def check_for_disconnections(timeout=300):
    # get the list of connected devices from the connected_devices dictionary
    for mac_address in connected_devices.keys():
        # if connected_devices[mac_address][1] == False:
        #     continue
        ip_address = ip_mac_mapping.get(mac_address)
        if not ip_address:
            continue
        ping = arp_ping(ip_address)
        if not ping:
            log_device_activity(mac_address, 'Disconnected')
            device_last_seen[mac_address] = (time.time(), False)
            connected_devices[mac_address] = (time.time(), False)
        elif ping:
            connected_devices[mac_address] = (time.time(), True)
            device_last_seen[mac_address] = time.time()
            connected_devices[mac_address] = (time.time(), True)

    return


def main():
    capture = pyshark.LiveCapture(interface='wlp4s0')
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

if __name__ == '__main__':
    main()
