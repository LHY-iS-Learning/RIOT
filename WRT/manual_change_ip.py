#!/opt/bin/python

import sqlite3
from subprocess import call

command = "iptables -D FORWARD -p tcp -d 17.142.160.59 --dport 443 -m mac --mac-source 70:ef:00:92:81:22 -j ACCEPT"
call(command, shell=True)

command = "iptables -I FORWARD -p tcp -d 1.2.3.4 --dport 443 -m mac --mac-source 70:ef:00:92:81:22 -j ACCEPT"
call(command, shell=True)

query = "update device set ip='1.2.3.4' where domain = 'apple.com' and ip = '17.142.160.59'"
try:
    conn = sqlite3.connect('device.db')
except:
    print "[ERROR] Fail to connect to database"

cursor = conn.cursor()
cursor.execute(query)
conn.commit()
conn.close()
