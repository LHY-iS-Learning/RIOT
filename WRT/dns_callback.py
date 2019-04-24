from scapy.all import *
import dpkt
from subprocess import call
import sqlite3
import datetime
from iptable_controller import obtainMudProfile
from send_email import alert
from update_ip import update_device_domains
from IoT_Classification import get_device_dhcp_info

# monitor network flow list
DELTA_TIME = datetime.timedelta(seconds = 1)
monitor_device = {}
temp_black_list = set()

def check_mud(pcap_file):
    with open(pcap_file) as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data
            dhcp = dpkt.dhcp.DHCP(udp.data)

            for opt in dhcp.opts:
                if opt[0] == 161: #161
                    print opt[1]
                    return opt[1]
    return False

def get_hostname(pcap_file):
    with open(pcap_file) as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data
            dhcp = dpkt.dhcp.DHCP(udp.data)

            for opt in dhcp.opts:
                if opt[0] == 12:
                    print opt[1]
                    return opt[1]
    return '***'

def pktHandler(pkt):
    try:
        mac_addr = str(pkt[Ether].src)
        if mac_addr in monitor_device.keys() and mac_addr not in temp_black_list:
            if datetime.datetime.now() < monitor_device[mac_addr]:
                print("[INFO] Keep monitoring " + mac_addr)
                wrpcap(mac_addr+".pcap", pkt, append=True)
            else:
                print("[INFO] Finish monitor " + mac_addr)
                temp_black_list.add(mac_addr)

                # to-do: send to server


                call('iptables -A FORWARD  -m mac --mac-source ' + mac_addr + ' -j DROP' + '', shell=True)
                print 'drop packets for mac:' + mac_addr
                
                try:
                    alert('wh2417@columbia.edu')
                    # update_suspicious(mac_addr)
                except Exception as e:
                    print e
                print "[INFO] send email to user"

                temp_black_list.remove(mac_addr)
                monitor_device.pop(mac_addr)

        else:
            standard_dns_callback(pkt)
    except:
        pass

#simulate source server for now
SourceServer = dict()

# lists of devices seen right now 
devices = set()
# router itself
devices.add("10:da:43:96:1d:64")


def standard_dns_callback(pkt):
    layers = list(layer_expand(pkt))

    if "DNS" in layers:
        dns_callback(pkt)

    elif "BOOTP" in layers:
        #features = get_device_dhcp_info(pkt)
        if False:
            # General Purpose device
            print("[INFO] " + str(features))
            
        else:
            print("BOOTP: " + pkt[Ether].src)
            mac_addr = str(pkt[Ether].src)

            try:
                if mac_addr not in devices:
                    search_mud_file(pkt)
                else:
                    pass
            except Exception as e:
                print "Line 77"
                print e

    else:
        pass
# blacklist for email
blacklist = set()

def search_mud_file(pkt):
    wrpcap("a.pcap", pkt)
    mud_addr = check_mud("a.pcap")
    mac_addr = str(pkt[Ether].src)
    hostname = get_hostname("a.pcap")

    if mud_addr:
        devices.add(mac_addr)
        print "[INFO] Obtain MudProfile"
        obtainMudProfile('iot', mac_addr, mud_addr)

    elif SourceServer.get(mac_addr) is not None:
        #download mud from source server
        print "[INFO] Download mud file from source server"
        
    else:
        print "[INFO] No source server entry"

        # Create a pcap file, monitor for one hour and send to server
        create_pcap_file(pkt)

        update_suspicious(mac_addr, hostname)

        print "[INFO] Successfully generate a mud like file" 

        # if not pkt[Ether].src in blacklist:
        #     pass
        #     update_suspicious(mac_addr)
        #     alert('wh2417@columbia.edu')

        # blacklist.add(pkt[Ether].src)
        # print blacklist

def update_suspicious(mac_addr, hostname):
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    cursor = conn.cursor()
    query = "INSERT INTO SUSPICIOUS(MAC, HOSTNAME) VALUES(?, ?)"
    cursor.execute(query, (mac_addr, hostname))
    conn.commit()
    conn.close()




def create_pcap_file(pkt):
    try:
        mac_addr = str(pkt[Ether].src)
        wrpcap(mac_addr+".pcap", pkt)
        end_time = datetime.datetime.now() + DELTA_TIME
        monitor_device[mac_addr] = end_time
        return True
    except Exception as e:
        print "Line 121"
        print e

        return False






#confirm DNS ans packet and parse for info
def dns_callback(pkt):

    if DNS in pkt and 'Ans' in pkt.summary():
        response = []

        for x in xrange(pkt[DNS].ancount):
            #capture the data in res packet
            # keep response in case need it
            response.append(pkt[DNSRR][x].rdata)

        try:
            device_dict = create_device_dic(pkt, response)
            update_device_domains(device_dict)

        except Exception as e:
            # print("Error: Unable to parse DNS ans packet")
            return

def create_device_dic(pkt, response):
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
    return device_dict

#expand the packet to check for DNS type
def layer_expand(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        yield packet.name

