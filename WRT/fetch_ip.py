#!/usr/bin/env python

import sys
import json
import socket
import os
from subprocess import Popen, PIPE, call
import sqlite3

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

def dst_or_src_dnsname(matches):
    if "ietf-acldns:src-dnsname" in matches["ipv4"]:
        return ["ietf-acldns:src-dnsname", "source-port"]
    elif "ietf-acldns:dst-dnsname" in matches["ipv4"]:
        return ["ietf-acldns:dst-dnsname", "destination-port"]

def get_prot(matches, dnsName):
    if("tcp" in matches):
        subport = matches["tcp"]
        prot = "tcp"
    elif("udp" in matches):
        subport = matches["udp"]
        prot = "udp"
    else:
        print("Error in Matches")
        return

    # subport["source-port"]["port"] 
    # or 
    # subport["destination-port"]["port"]
    dport = str(subport[dnsName]["port"])
    return prot, dport

def get_destName(matches, dnsName):
    return matches["ipv4"][dnsName][:-1]

def get_dest_ip(dstName):
    p = Popen(['dig', '+short', dstName], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")

    destIpList = output.split('\n')[:-1]
    res = []
    for destIp in destIpList:
        res.append(destIp)
        for c in destIp:
            if c.isalpha():
                res.remove(destIp)
                break

    return res

def parse_info(matches):
    # get dst or src
    # pre-process
    dnsName = dst_or_src_dnsname(matches)
    # get protocol and dst port
    prot, dport = get_prot(matches, dnsName[1])
    # get dst Ip list
    dstName = get_destName(matches, dnsName[0])
    dstIpList = get_dest_ip(dstName)
    # get ACCEPT or REJECT
    target = matches["actions"]["forwarding"].upper()
    
    return prot, dport, dstIpList, target, dstName

def check_SQL_table():
    #configure database and connect
    #check if device database exist
    exists = os.path.exists('device.db')

    if not exists:
        #create db and insert main schema
        conn = sqlite3.connect('device.db')
        print("Database has been created")
        conn.execute('CREATE TABLE DEVICE (NAME CHAR(20) NOT NULL, DOMAIN CHAR(50) NOT NULL, IP CHAR(20) NOT NULL, PORT CHAR(20) NOT NULL, PROTOCOL CHAR(20) NOT NULL);')
        print("Main device table created")
        conn.commit() 

def has_dup(cursor, mac_addr, dstName):
    query = "select NAME, DOMAIN, IP, PORT, PROTOCOL from DEVICE WHERE NAME = '{0}' and DOMAIN = '{1}'".format(mac_addr, dstName)
    try:
        res = cursor.execute(query)
    except Exception as e:
        print e
    size = len(res.fetchall())
    # size != 0, has dup, return true
    return size != 0

def ACLtoIPTable(acl, mac_addr):

    # open database
    check_SQL_table()
    conn = sqlite3.connect('device.db')
    print("Database is running")
    cursor = conn.cursor()

    ace = acl[0]["aces"]
    for index in ace:
        matches = index["matches"]
            #Confirm that matches has valid info for dest addr
        if("ietf-acldns:src-dnsname" not in matches["ipv4"] and \
           "ietf-acldns:dst-dnsname" not in matches["ipv4"]):
            continue

        prot, dport, dstIpList, target, dstName = parse_info(matches)

        # for each dst IP
        print("*********" + dstName + "*************")
        if not has_dup(cursor, mac_addr, dstName):
            for dstIp in dstIpList:
                call('iptables -A FORWARD -p ' + prot + ' -d ' + dstIp + ' --dport ' + dport + ' -m mac --mac-source ' + mac_addr + ' -j ' + target + '', shell=True)
                print("[INFO] Implemented rule for: source-> " + mac_addr + " dest-> " + dstIp)
                print ""
                query = "INSERT INTO DEVICE(NAME, DOMAIN, IP, PORT, PROTOCOL) VALUES('{0}','{1}','{2}','{3}','{4}')".format(mac_addr, dstName, dstIp, dport, prot)
                cursor.execute(query)
                conn.commit()
        else:
            print("[INFO] Rules exist for source-> " + mac_addr + " dest-> " + dstName)
        print("**********************")
    
    #call ('iptables -I FORWARD -d 17.142.160.59 -j DROP', shell=True)
    call('iptables -A FORWARD -m mac --mac-source ' + mac_addr + ' -j DROP' + '', shell=True)
    conn.close()


