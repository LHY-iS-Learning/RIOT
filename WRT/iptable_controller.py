#!/usr/bin/env python
#controller that will monitor for new IoT devices joining and
#request MUD Profile from croud-sourcing server to implement

import sys
import json
import os
import urllib2
from fetch_ip import implementIPTablesByJson
import ssl

#Obtain MUD Profile from server based on Device Type
def obtainMudProfile(device, mac_addr, mud_addr):

    if(device == 'iot'):
        print("SUCCESS")
    print("log: {0} {1}".format(device, mac_addr))

    mud_addr = 'http://lhy.im/api/products/MUDProfile/' + device + '.json'

    if(device):
        #send request to API for device's MUD Profile
        req = urllib2.Request(mud_addr)
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

        result = urllib2.urlopen(req, context = gcontext)

        profile = result.read().decode('utf-8')

        #print(profile)
        #call fetch_ip.py's function to implement MUD profile
        implementIPTablesByJson(profile, mac_addr)

    else:
        print('name of device is missing')




if __name__ == "__main__":
    obtainMudProfile('iot', '70:ef:00:92:81:22', 's')
