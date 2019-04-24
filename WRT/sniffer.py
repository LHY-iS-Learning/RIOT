#!/opt/bin/python

#Workspace for scapy's sniff to monitor for IoT device activities
#Detect new joining IoT devices and dynamically update domain endpoints IP Addrs

from scapy.all import *
import sqlite3
import os

from dns_callback import pktHandler

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
    conn.execute('CREATE TABLE SUSPICIOUS (MAC CHAR(20) NOT NULL UNIQUE, HOSTNAME CHAR(20) NOT NULL);')
    conn.execute('CREATE TABLE BLOCKED (MAC CHAR(20) NOT NULL UNIQUE, HOSTNAME CHAR(20) NOT NULL);')
    print("Main device table created")


cursor = conn.cursor()

#capture all packets
try:
    sniff(prn=pktHandler)
except Exception as e:
    print "Sniffer file"
    print e
