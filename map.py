#!/usr/bin/env python


# draws a line between two ip location


from webbrowser import open_new_tab
from ipaddress import ip_address
import folium
import geocoder
import re  

ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'   #regex for finding the ip addr

ip_pairs = [
        {"source_ip": "8.8.8.8", "destination_ip": "8.8.8.8"},
]

def ip_info(ipaddr):
    location = geocoder.ip(ipaddr)
    try:
        if ip_address(ipaddr):
            if location:
                latitude, longitude = location.latlng
                return latitude,longitude
    except:
        return False,False


def markonmap():
    
    #mark the first src_ip and dst_ip
    location1 = ip_info(ip_pairs[0]["source_ip"])
    location2 = ip_info(ip_pairs[0]["destination_ip"])

    # Create a map centered between source and destination of the first pair
    map_center = [(location1[0] + location2[0]) / 2, (location1[1] + location2[1]) / 2]
    m = folium.Map(location=map_center, zoom_start=2)
    
    if location1 and location2:
        try:
            # Draw lines and markers for each IP pair
            for pair in range (len(ip_pairs)):
    
                location1 = ip_info(ip_pairs[pair]['source_ip'])
                location2 = ip_info(ip_pairs[pair]['destination_ip'])

                folium.PolyLine([location1, location2], color="blue").add_to(m)
                folium.Marker(location1, tooltip="Source IP").add_to(m)
                folium.Marker(location2, tooltip="Destination IP").add_to(m)

            # Save the map to an HTML file
            m.save("map.html")
    
        except:
            print('[+] Cannot Fetch Location!')



#if __name__ == '__main__':
with open("ip.txt", "r") as file:
    lines = file.read().splitlines()

for x in lines:
    # Find all IP addresses in the text
    ip_addresses = re.findall(ip_pattern, x)

    if len(ip_addresses) >= 2:
        ip1 = ip_addresses[0]
        ip2 = ip_addresses[1]

        #content of the dictionary
        dict_ip = {'source_ip': '','destination_ip':''}
        #setting the ip
        dict_ip['source_ip'] = ip1
        dict_ip['destination_ip'] = ip2

        #appending
        ip_pairs.append(dict_ip)

    else:
        pass

#marking the location on map
markonmap()


#opening the file on browser
try:
    open_new_tab('./map.html')
except:
    print('[+] File Not Found!')