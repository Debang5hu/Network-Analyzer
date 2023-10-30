#!/usr/bin/env python


# draws a line between the location of your ip and destination ip 

#kudos to https://medium.com/vinsloev-academy/python-cybersecurity-network-tracking-using-wireshark-and-google-maps-2adf3e497a93

# <---- KML ---->
#KML is a file format used to display geographic data in an Earth browser such as Google Earth
#link: https://en.wikipedia.org/wiki/Keyhole_Markup_Language


#import folium
import dpkt
import pygeoip  #for mapping the location
import socket
from webbrowser import open_new_tab
from time import sleep


gi = pygeoip.GeoIP('GeoLiteCity.dat')  #db to be downloaded later!


#placing the values to kml
def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name('103.55.96.184')  #my public ip : 103.55.96.184
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        )%(dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except:
        return ''
    

#for plotting the ip
def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # 'inet_ntoa': Converts an IP address to human readable dotted format
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            KML = retKML(dst, src)
            kmlPts = kmlPts + KML
        except:
            pass
    return kmlPts

#initialising the kml 
def main():
    f = open('packet.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    #header
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">' \
                '<LineStyle>' \
                '<width>1.5</width>' \
                '<color>501400E6</color>' \
                '</LineStyle>' \
                '</Style>'
    
    #footer
    kmlfooter = '</Document>\n</kml>\n'

    #body
    kmldoc=kmlheader + plotIPs(pcap) + kmlfooter
    
    #writting the output to a .kml file
    with open('layout.kml','w') as fh:
        fh.write(kmldoc)
    
    print('[+] File Saved!')
    print('[+] Create a map and import the "layout.kml" file in the opened website to see the route!')
    
    sleep(3)
    
    #opening it in new tab of default browser
    open_new_tab('https://www.google.com/mymaps')

    #closing the file
    f.close()

#calling the main func
main()


