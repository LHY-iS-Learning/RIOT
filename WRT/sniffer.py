#!/opt/bin/python

#Workspace for scapy's sniff to monitor for IoT device activities
#Detect new joining IoT devices and dynamically update domain endpoints IP Addrs

from scapy.all import *
import sqlite3
import os
from subprocess import call
from iptable_controller import obtainMudProfile

#update database when new ACL is detected
def update_device_domains(device_dict):
    valid = False
    port = ''
    protocol = ''
    #name = device_dict['mac_address']
    name = 'd0:25:98:ee:22:7f'
    domain = device_dict['domains'][0]['domain'][:-1]
    query = "SELECT NAME, DOMAIN, IP, PORT, PROTOCOL from DEVICE WHERE NAME = " + "'{0}'".format(name) + " AND DOMAIN = " + "'{0}'".format(domain)
    answer = cursor.execute(query)

    ips = []
    for rule in answer.fetchall():
        ips.append(rule[2])
        port = rule[3]
        protocol = rule[4]

    if ips:
        for db_ip in device_dict['domains'][0].get('ips'):

            if db_ip in ips:
                #No change of ip for domain name
                pass
            else:
                #IP has changed for domain name
                #automatically implement new set of ip
                valid = True

    if valid:
        #drop current rules and implement with new ips
        print("Updating Rules")
        #do for loop again for each ip and create matches for each to form overall acl, also get tcp or udp and port
        update_ipfilter(device_dict, port, protocol, ips)
        valid = False


#expand the packet to check for DNS type
def layer_expand(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        yield packet.name

#confirm DNS ans packet and parse for info
def dns_callback(pkt):

    if DNS in pkt and 'Ans' in pkt.summary():
        response = []

        for x in xrange(pkt[DNS].ancount):
            #capture the data in res packet
            response.append(pkt[DNSRR][x].rdata)

        try:
            #obtain dictionary of device description
            device_dict = dict()
            device_dict['mac_address'] = pkt[Ether].dst
            device_dict['ip_address'] = pkt.getlayer(IP).dst

            domains = []

            #obtain dictionary of domain dsecription
            domain_dict = dict()
            domain_dict['domain'] = pkt[DNSQR].qname
            domain_dict['ips'] = response
            domains.append(domain_dict)

            device_dict['domains'] = domains

            update_device_domains(device_dict)



        except Exception as e:
            print("Error: Unable to parse DNS ans packet")
            return

#filter for DNS packets only
def standard_dns_callback(pkt):
    layers = list(layer_expand(pkt))

    if "DNS" in layers:
        dns_callback(pkt)

    elif "BOOTP" in layers:
	print(pkt[Ether].src)
	mac_addr = str(pkt[Ether].src)

	if mac_addr not in devices:
	    devices.add(mac_addr)
	    obtainMudProfile('iot_device', mac_addr)

	else:
	    pass

    else:
        pass


def pktHandler(pkt):
    try:
        standard_dns_callback(pkt)
    except Exception as e:
        print("Error: filtering for DNS failed")
        pass

def update_ipfilter(device_dict, port, protocol, ips):

    ip_protocol = str(protocol)
    source = str(device_dict['ip_address'])
    target = "ACCEPT"
    dport = str(port)
    domain = device_dict['domains'][0]['domain'][:-1]

    #delete old ips from Database
    #mac_source = device_dict['mac_address']
    mac_source = 'd0:25:98:ee:22:7f'

    old_query = "DELETE FROM DEVICE WHERE NAME = '{0}' AND DOMAIN = '{1}'".format(mac_source, domain)
    cursor.execute(old_query)
    conn.commit()

    #Remove outdated iptables rules for specific IoT Device and domain endpoint
    for old_ip in ips:
        old_dest = old_ip
        call('iptables -D INPUT -p ' + ip_protocol + ' -d '+ old_dest + ' --dport ' + dport + ' -m mac --mac-source ' + mac_source + ' -j ' + target + '', shell=True)


    #Append new iptables rules for specific IoT Device and domain endpoint
    for db_ip in device_dict['domains'][0].get('ips'):
        destination = str(db_ip)
        print("Source: {0} destination: {1} protocol: {2} port: {3}".format(mac_source, destination, ip_protocol, dport))

        call('iptables -A INPUT -p ' + ip_protocol + ' -d '+ destination + ' --dport ' + dport + ' -m mac --mac-source ' + mac_source + ' -j ' + target + '', shell=True)
        #update database with new ip
        query = "INSERT INTO DEVICE(NAME, DOMAIN, IP, PORT, PROTOCOL) VALUES('{0}','{1}','{2}','{3}','{4}')".format(mac_source, str(device_dict['domains'][0]['domain']), destination, dport, ip_protocol)

        cursor.execute(query)
        conn.commit()



#check if device database exist
exists = os.path.exists('device.db')
devices = set()
devices.add("10:da:43:96:1d:64")

if exists:
    conn = sqlite3.connect('device.db')
    print("Database is running")

else:
    #create db and insert main schema
    conn = sqlite3.connect('device.db')
    print("Database has been created")
    conn.execute('CREATE TABLE DEVICE (NAME CHAR(20) NOT NULL, DOMAIN CHAR(50) NOT NULL, IP CHAR(20) NOT NULL, PORT CHAR(20) NOT NULL, PROTOCOL CHAR(20) NOT NULL);')
    print("Main device table created")


cursor = conn.cursor()

#capture all packets
sniff(prn=pktHandler)
