#!/opt/bin/python

#Workspace for scapy's sniff to monitor for IoT device activities
#Detect new joining IoT devices and dynamically update domain endpoints IP Addrs

from scapy.all import *
import sqlite3
import os
from subprocess import call
from iptable_controller import obtainMudProfile
import random
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from update_ip import update_device_domains

import dpkt

#update database when new ACL is detected


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
            # print("Error: Unable to parse DNS ans packet")
            return

#send alert email to user
def alert(useraddr):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    # password = raw_input('Type in your email password:')
    #password = getpass.getpass("Type in your email password: ")
    password = '1234567890s'
    #sender = 'harrisonhuang1025@gmail.com' 
    sender = 'lhyemailsender@gmail.com'
    server.login(sender, password)

    message = '''\
    <html>
        <h1>FAIL to find a MUD for this device</h1>
        <p> Go to the router address </p>
        <a href = '192.168.2.1'> My router </a>
    </html>
    '''
    # msg = MIMEText('FAIL to find a MUD for this device', 'plain', 'utf-8')
    msg = MIMEText(message, 'html')

    msg['Subject'] = Header('Alert from router', 'utf-8')
    msg['From'] = sender
    msg['To'] = useraddr
    try:
        server.sendmail(sender, useraddr, msg.as_string())
        print 'email sended'
    except:
        print 'fail to send email'
    finally:
        server.quit()
#simulate source server for now
SourceServer = dict()
# SourceServer['00:9D:6B:41:6F:B0'] = 0

#filter for DNS packets only
def standard_dns_callback(pkt):
    layers = list(layer_expand(pkt))

    if "DNS" in layers:
        dns_callback(pkt)

    elif "BOOTP" in layers:
    	print("BOOTP: " + pkt[Ether].src)
    	mac_addr = str(pkt[Ether].src)
        
    	if mac_addr not in devices:
            wrpcap("a.pcap", pkt)
            mud_addr = check_mud("a.pcap")
            print(mud_addr) 
            if mud_addr:
                devices.add(mac_addr)
                print "Obtain MudProfile"
                obtainMudProfile('iot', mac_addr, mud_addr)
            elif SourceServer.get(mac_addr) is not None:
                #download mud from source server
                print "download mud file from source server"
                # pass
            else:
                print "no MUD, not source server entry"
                if not pkt[Ether].src in blacklist:
                    pass
                    alert('wh2417@columbia.edu')

                blacklist.add(pkt[Ether].src)
                # print blacklist
                # iptables -A FORWARD -m mac --mac-source 00:0c:29:27:55:3F -j DROP
                mac_source = pkt[Ether].src
                call('iptables -A FORWARD  -m mac --mac-source ' + mac_source + ' -j DROP' + '', shell=True)
                print 'drop packets for mac:' + mac_source
    	else:
    	    pass

    else:
        pass


def check_mud(pcap_file):
    with open(pcap_file) as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data
            dhcp = dpkt.dhcp.DHCP(udp.data)

            for opt in dhcp.opts:
                if opt[0] == 12: #161
                    print opt[1]
                    return opt[1]
    return False


def pktHandler(pkt):
    try:
        standard_dns_callback(pkt)
        # print devices
    except Exception as e:
        #print("Error: filtering for DNS failed")
        pass

#check if device database exist
exists = os.path.exists('device.db')
devices = set()
devices.add("10:da:43:96:1d:64")
blacklist = set()

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
