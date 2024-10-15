def parse_router_devices(html_str):
    from bs4 import BeautifulSoup

    devices = {}
    soup = BeautifulSoup(html_str, 'html.parser')

    # Find the table with class "table100"
    table = soup.find('table', {'class': 'table100'})
    if not table:
        return devices  # Return empty dict if table not found

    rows = table.find_all('tr')

    current_device_data = {}
    current_mac_address = None

    for tr in rows:
        # Check for separator (indicates new device)
        hr = tr.find('hr')
        if hr:
            # Separator found; save current device data
            if current_mac_address:
                devices[current_mac_address] = current_device_data
            # Reset for next device
            current_device_data = {}
            current_mac_address = None
            continue

        # Get key and value
        th = tr.find('th', {'scope': 'row'})
        td = tr.find('td', {'class': 'col2'})

        if th and td:
            key = th.get_text(strip=True)
            value = td.get_text(separator=' ', strip=True)

            # Handle special cases
            if key == 'MAC Address':
                current_mac_address = value
            elif key == 'IPv4 Address / Name':
                parts = value.split(' / ')
                ip_address = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else ''
                current_device_data['IPv4 Address'] = ip_address
                current_device_data['Name'] = name
            elif key == 'Connection Type':
                # Extract text from <pre> element
                pre = td.find('pre', {'class': 'column'})
                if pre:
                    value = pre.get_text(separator=' ', strip=True)
                current_device_data[key] = value
            else:
                # Store repeated keys as lists
                if key in current_device_data:
                    if isinstance(current_device_data[key], list):
                        current_device_data[key].append(value)
                    else:
                        current_device_data[key] = [current_device_data[key], value]
                else:
                    current_device_data[key] = value

    # Add the last device data
    if current_mac_address:
        devices[current_mac_address] = current_device_data

    return devices

if __name__ == '__main__':
    with open('device-list.txt', 'r') as f:
        html_str = f.read()
    devices = parse_router_devices(html_str)
    for mac_address, device_data in devices.items():
        print(mac_address)
        for key, value in device_data.items():
            print(f'  {key}: {value}')
        print()
