from flask import Flask
from flask import render_template 
from flask import request, redirect, url_for
from flask_bootstrap import Bootstrap
import sqlite3
from subprocess import call

app = Flask(__name__)
bootstrap = Bootstrap(app)
@app.route('/')
def admin():
    rows = get_db_entry()
    return render_template("admin.html", rows = rows)

@app.route('/blocked_devices')
def blocked_list():
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    query = "SELECT * FROM BLOCKED"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return render_template("blocked.html", rows = rows)

@app.route('/connected_devices')
def connected_list():
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    query = "SELECT * FROM DEVICE"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return render_template("connected.html", rows = rows)


def get_db_entry():
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    query = "SELECT * FROM SUSPICIOUS"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route('/block_page', methods = ['GET', 'POST'])
def block():
    mac_addr = request.form.keys()[0]
    # ip = request.form.values()[0]
    # print "blocking {ip} for {mac}".format(ip = ip, mac = mac_addr)
    print "blocking "+ mac_addr
    iptables_block(mac_addr)
    insert_into_blocked(mac_addr)
    return redirect(url_for('admin'))

@app.route('/keep_block', methods = ['GET', 'POST'])
def keep_block():
    mac_addr = request.form.keys()[0]
    hostname = request.form.values()[0]
    print "keep blocking "+ mac_addr
    delete_from_suspicious(mac_addr)
    insert_into_blocked(mac_addr, hostname)
    return redirect(url_for('admin'))

@app.route('/allow_page', methods = ['GET', 'POST'])
def allow():
    mac_addr = request.form.keys()[0]
    # ip = request.form.values()[0]
    # print "allowing {ip} for {mac}".format(ip = ip, mac = mac_addr)
    print "allowing " + mac_addr
    iptables_delete(mac_addr)
    delete_from_blocked(mac_addr)
    return redirect(url_for('admin'))

def iptables_delete(mac_addr):
    call("iptables -D FORWARD -m mac --mac-source {mac} -j DROP".format(mac = mac_addr), shell = True)
    try:
        delete_from_suspicious(mac_addr)
    except Exception as e:
        print e

def iptables_block(mac_addr):
    call("iptables -I FORWARD -m mac --mac-source {mac} -j DROP".format(mac = mac_addr), shell = True)
    delete_from_suspicious(mac_addr)

def delete_from_suspicious(mac_addr):
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    cursor = conn.cursor()
    query = "DELETE FROM SUSPICIOUS WHERE MAC = (?)"
    cursor.execute(query, (mac_addr,))
    conn.commit()
    conn.close()

def insert_into_blocked(mac_addr, hostname = '***'):
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    cursor = conn.cursor()
    query = "INSERT INTO BLOCKED(MAC, HOSTNAME) VALUES(?, ?)"
    cursor.execute(query, (mac_addr, hostname))
    conn.commit()
    conn.close()

def delete_from_blocked(mac_addr):
    try:
        conn = sqlite3.connect("device.db")
    except:
        print "[ERROR] Fail to connect to database"

    cursor = conn.cursor()
    query = "DELETE FROM BLOCKED WHERE MAC = (?)"
    cursor.execute(query, (mac_addr,))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # app.run(host = '0.0.0.0')
    app.run(debug = True, host = '0.0.0.0')





