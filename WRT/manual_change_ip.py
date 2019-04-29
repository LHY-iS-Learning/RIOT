#!/opt/bin/python

import sqlite3
from subprocess import call

command = "iptables -D FORWARD -p tcp -d 93.184.216.34 --dport 80 -m mac --mac-source B8:27:EB:D3:0E:76 -j ACCEPT"
call(command, shell=True)
call(command, shell=True)
call(command, shell=True)

command = "iptables -I FORWARD -p tcp -d 1.2.3.4 --dport 80 -m mac --mac-source B8:27:EB:D3:0E:76 -j ACCEPT"
call(command, shell=True)

query1 = "update device set ip='1.2.3.4' where domain = 'www.example.com' and ip = '93.184.216.34'"
query2 = "update device set ip='1.2.3.4' where domain = 'www.example.org' and ip = '93.184.216.34'"
query3 = "update device set ip='1.2.3.4' where domain = 'www.example.net' and ip = '93.184.216.34'"
try:
    conn = sqlite3.connect('device.db')
except:
    print "[ERROR] Fail to connect to database"

cursor = conn.cursor()
cursor.execute(query1)
cursor.execute(query2)
cursor.execute(query3)
conn.commit()
conn.close()
