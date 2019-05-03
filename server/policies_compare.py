from scapy.all import *
import pickle
import os
import argparse

global mac
global policies

THRESH_HOLD = 0.8

policies = {}
policies["from device policies"] = set()
policies["to device policies"] = set()

def extract_policy(pkt):
    global mac
    global policies
    protocol = None
    domain = None

    if pkt[Ether].src == mac:
        if TCP in pkt:
            protocol = 'tcp ' + str(pkt[TCP].dport)
        elif UDP in pkt:
            protocol = 'udp ' + str(pkt[UDP].dport)
        if DNSQR in pkt:
            domain = pkt[DNSQR].qname.decode('ascii')
            policies["from device policies"].add(protocol + " " + domain)
    else:
        if TCP in pkt:
            protocol = 'tcp ' + str(pkt[TCP].sport)
        elif UDP in pkt:
            protocol = 'udp ' + str(pkt[UDP].sport)
        if DNSQR in pkt:
            domain = pkt[DNSQR].qname.decode('ascii')
            policies["to device policies"].add(protocol + " " + domain)

def compare_policy():
    global mac
    global policies
    parser = argparse.ArgumentParser()
    parser.add_argument('unknown', help="Unknown device to be identified")
    args = parser.parse_args()  # unknown#08-02-8e-2b-24-b4.pcap

    name_mac = args.unknown.replace(".pcap", "")
    # print(name_mac)
    mac = name_mac.split('#')[1].replace('-', ':')
    # mac = '08:02:8e:2b:24:b4'  # ARLO baby monitor
    # devicename = 'ARLO5'

    sniff(offline= args.unknown, prn=extract_policy)
    # print(policies)
    matches = float("-inf")
    best_match = None
    path = 'known_devices'
    known_devices = os.listdir(path)
    for f in known_devices:
        known = pickle.load( open(path + '/' + f, "rb" ) )
        # print(known)
        try:
            f_match = 1 - len(policies["from device policies"] - known["from device policies"]) / len(policies["from device policies"])
        except:
            f_match = 0
        try:
            t_match = 1 - len(policies["to device policies"] - known["to device policies"]) / len(policies["to device policies"])
        except:
            t_match = 0
        if f_match + t_match > matches:
            matches = f_match + t_match
            best_match = f
    # print(matches)
    outputpath = 'output_pkl/'
    if matches > THRESH_HOLD:
        pickle.dump( policies, open(outputpath + '#' + best_match, "wb" ) )
        return (True, best_match.replace('.pkl', ''), matches)
    else:
        pickle.dump( policies, open(outputpath + 'unknown' + '#' + mac.replace(':', '-') + '.pkl', "wb" ) )
        return (False, 'unknown' + '#' + mac.replace(':', '-'), matches)
