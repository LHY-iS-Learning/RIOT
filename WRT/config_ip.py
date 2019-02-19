#!/usr/bin/env python
#python iptable configuration
#Implement iptables rules from MUD Profile for specific IoT Device

import sys
import json
#import iptc
import socket
import os
from subprocess import call
import sqlite3

#Manually inserting MUD Profile
def implementIPTables(file):
    #obtain desired MUD-like object to parse.
    try:
        mudfile = open(file, 'r').read()

    except FileNotFoundError:
        print("File does not exist")
        sys.exit()

    #obtain device ip addr
    head, tail = os.path.split(file)
    filename = head.split('/')[-1]

    #verify and obtain if file content is JSON format
    try:
        json_object = json.loads(mudfile)

    except ValueError:
        print("Incorrect File Content Format: JSON")
        sys.exit()

    #parse mud-like json for ACL
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]


    ACLtoIPTable(ACL_array, filename)

#Obtained MUD Profile from MUD Profile Server
def implementIPTablesByJson(file, mac_addr):
    #obtain desired MUD-like object to parse.
    #verify and obtain if file content is JSON format
    try:
        json_object = json.loads(file)

    except ValueError:
        print("Incorrect File Content Format: JSON")
        sys.exit()

    print("Parsing ACL from Mud Profile")
    #parse mud-like json for ACL
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]


    ACLtoIPTable(ACL_array, mac_addr)

#parse device acl to iptable
def ACLtoIPTable(acl, mac_addr):
    match, action, endpoint, protocol, subport = '','','','',''

    #configure database and connect
    #check if device database exist
    exists = os.path.exists('device.db')

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

    #First set of ACES
    ace = acl[0]["aces"]

    print("Implementing iptables rules")

    #implement IPTables for each matches with their respective demands
    for index in ace:
        matches = index["matches"]


	#Confirm that matches has valid info for dest addr
        if("ietf-acldns:src-dnsname" not in matches["ipv4"] and "ietf-acldns:dst-dnsname" not in matches["ipv4"]):
            continue


        #capture essential info
        action = matches["actions"]
        endpoint = matches["ipv4"]
        if "ietf-acldns:src-dnsname" in matches["ipv4"]:
            dest_name = endpoint["ietf-acldns:src-dnsname"][:-1]
        elif "ietf-acldns:dst-dnsname" in matches["ipv4"]:
            dest_name = endpoint["ietf-acldns:dst-dnsname"][:-1]
        else:
            continue


	    #resolve dest address
        dest_addr = socket.gethostbyname(dest_name)

        mac_source = mac_addr
        destination = dest_addr


        if("tcp" in matches):
            subport = matches["tcp"]
            protocol = "tcp"
        elif("udp" in matches):
            subport = matches["udp"]
            protocol = "udp"
        else:
            print("Error in Matches")
            pass


        target = action["forwarding"].upper()

        if "ietf-acldns:src-dnsname" in matches["ipv4"]:
	        dport = str(subport["source-port"]["port"])
        elif "ietf-acldns:dst-dnsname" in matches["ipv4"]:
            dport = str(subport["destination-port"]["port"])
        else:
            continue


        #Append iptables rule to INPUT chain
        call('iptables -A INPUT -p ' + protocol + ' -d ' + destination + ' --dport ' + dport + ' -m mac --mac-source ' + mac_source + ' -j ' + target + '', shell=True)

        print("Implemented rule for: source-> " + mac_source + " dest-> " + destination)

        #Add to database to track
        name = mac_source
        query = "INSERT INTO DEVICE(NAME, DOMAIN, IP, PORT, PROTOCOL) VALUES('{0}','{1}','{2}','{3}','{4}')".format(name, dest_name, destination, dport, protocol)


        print(query)
        cursor.execute(query)
        conn.commit()


#Below is iptables implementation using python-iptables
    """
	chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")

        #for test, just need one
        rule = iptc.Rule()
        rule.out_interface = "eth+"
        rule.src = filename

        rule.dst = dest_addr
        rule.target = iptc.Target(rule, action["forwarding"].upper())

        if("tcp" in matches):
            protocol = matches["tcp"]
            rule.protocol = "tcp"
	    match = iptc.Match(rule, "tcp")

        elif("udp" in matches):
	    protocol = matches["udp"]
            rule.protocol = "udp"
	    match = iptc.Match(rule, "udp")

        else:
            print("Error in matches")
            pass


        match.dport = str(protocol["source-port"]["port"])
        rule.add_match(match)
	chain.insert_rule(rule)

    	print("IPTables Rules implemented for %s" % rule.src)


    #Deny all packets from any other external endpoints
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.out_interface = "eth+"
    rule.src = filename
    rule.target = iptc.Target(rule, "DROP")
    chain.insert_rule(rule)
    """
    #Append DROP iptables rule to INPUT chain
    target = "DROP"
    call('iptables -A INPUT -m mac --mac-source ' + mac_source + ' -j ' + target + '', shell=True)



#If developer wants to run script on command line:~$ python config_ip [MUD-like file]
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Incorrect amount of arguments")
        sys.exit()

    arg = sys.argv[1]
    implementIPTables(arg)
